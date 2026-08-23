//! Paging at the HTTP boundary: opaque page tokens, and filtered pages.
//!
//! # The two halves
//!
//! The backend pages over its own sorted index ([`PageRequest`], [`Page`]).
//! This module converts between that and the wire: a `pageToken` is the
//! backend's cursor, base64url-encoded so clients treat it as opaque and do not
//! build one by hand.
//!
//! # Why filtering needs a loop
//!
//! Rustberg filters listings by policy, so a backend page of 100 rows can yield
//! anywhere from 0 to 100 visible ones. Two obvious approaches are both wrong:
//!
//! - **Slice first, filter after** returns short pages, and returns an *empty*
//!   page whenever a whole backend page is unpermitted — which many clients read
//!   as the end of the list, silently truncating results.
//! - **Read everything, then filter and slice** is correct but costs the whole
//!   listing on every request, which is what this replaces.
//!
//! So [`collect_page`] pulls from the backend and evaluates until the page is
//! full or the source is exhausted, and the token it returns is the backend
//! cursor of the last row *kept*. The honest cost is one policy evaluation per
//! row **scanned**, not per row returned: a principal permitted to see very
//! little pays for the rows skipped on its behalf.
//!
//! That cost is bounded. [`MAX_SCAN`] caps how many rows one request may examine,
//! so a restrictive policy degrades into more pages rather than one unbounded
//! scan. Hitting the cap returns a short page *with* a cursor, which is exactly
//! the "keep going" signal — no result is lost.
//!
//! # A batch must advance the cursor, or the loop is infinite
//!
//! The loop's only exits are "page full", "source exhausted" and "scan cap
//! reached", and all three are driven by rows *arriving*. A backend that answers
//! with **no entries and a next cursor** satisfies none of them: nothing is
//! scanned, so the cap never trips, and the cursor never moves, so the next
//! fetch is byte-identical to the last. The request then spins forever, holding
//! a worker and burning CPU.
//!
//! That page shape is not hypothetical. [`Page::from_probe`] cannot produce it,
//! but two sources build pages by hand and both can: a `rest` mount forwards
//! whatever the remote catalog answered, and a remote is free to send an empty
//! `identifiers` list with a `next-page-token`; and the federated root listing
//! drops namespaces a mount shadows, which can empty a page that still reports
//! more to come. The first is *remote-controlled*, which makes it a denial of
//! service by a catalog somebody else operates.
//!
//! So the loop reads [`Page::next`] — the cursor for the page *after* this one —
//! whenever a batch yields nothing to advance past. That is the correct resume
//! point for an empty page and costs nothing on the ordinary path. If even that
//! fails to move the cursor, the source cannot make progress and the listing
//! ends: repetition a client can see is bad, and a hang is worse.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;

use crate::catalog::{DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, Page, PageRequest};
use crate::error::{AppError, Result};

/// Most rows one request may examine before yielding a short page.
///
/// Ten full pages' worth. A caller whose policy hides almost everything still
/// makes progress — each request advances the cursor by up to this many rows —
/// without any single request scanning an entire catalog.
pub const MAX_SCAN: usize = MAX_PAGE_SIZE * 10;

/// Pagination query parameters, as the Iceberg REST spec spells them.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct PaginationQuery {
    /// Opaque token from a previous response's `next-page-token`.
    #[serde(rename = "pageToken")]
    pub page_token: Option<String>,

    /// Maximum items to return. Clamped to [`MAX_PAGE_SIZE`].
    #[serde(rename = "pageSize")]
    pub page_size: Option<usize>,
}

impl PaginationQuery {
    /// Builds a query from the two raw parameters.
    ///
    /// Each list endpoint declares `pageToken` and `pageSize` on its own query
    /// struct rather than `#[serde(flatten)]`-ing this one in. Flattening forces
    /// serde into `deserialize_any`, and a URL query yields every value as a
    /// string, so `pageSize=2` fails to parse as a number and the request becomes
    /// a `400`. Two explicit fields per endpoint is the cheaper trade.
    pub fn new(page_token: Option<String>, page_size: Option<usize>) -> Self {
        Self {
            page_token,
            page_size,
        }
    }

    /// The effective page size, clamped to the permitted range.
    pub fn effective_page_size(&self) -> usize {
        self.page_size
            .map(|size| size.clamp(1, MAX_PAGE_SIZE))
            .unwrap_or(DEFAULT_PAGE_SIZE)
    }

    /// Converts the query into a backend page request.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::BadRequest`] if a token was supplied but cannot be
    /// decoded. Silently restarting from page one would make a client with a
    /// corrupted token loop over the first page forever instead of failing.
    pub fn to_request(&self) -> Result<PageRequest> {
        Ok(PageRequest {
            after: self.decode_cursor()?,
            limit: self.effective_page_size(),
        })
    }

    /// Decodes the page token into a backend cursor.
    fn decode_cursor(&self) -> Result<Option<String>> {
        let Some(token) = self.page_token.as_ref() else {
            return Ok(None);
        };

        let bytes = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| AppError::BadRequest("Invalid page token".to_string()))?;

        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| AppError::BadRequest("Invalid page token".to_string()))
    }
}

/// Encodes a backend cursor as an opaque page token.
///
/// Base64url carries the unit separator that namespace keys contain, and signals
/// to clients that the value is not meant to be parsed or constructed.
pub fn encode_token(cursor: &str) -> String {
    URL_SAFE_NO_PAD.encode(cursor.as_bytes())
}

/// A page of results ready to serialise, with its next-page token.
#[derive(Debug)]
pub struct FilteredPage<T> {
    /// Items the caller may see.
    pub items: Vec<T>,
    /// Token to fetch the next page, absent when the source is exhausted.
    pub next_page_token: Option<String>,
}

/// Fills a page from `fetch`, keeping only rows `visible` accepts.
///
/// `fetch` is called repeatedly with an advancing cursor. Iteration stops when
/// the page is full, the source is exhausted, or [`MAX_SCAN`] rows have been
/// examined — see the module docs for why all three are needed.
///
/// # Errors
///
/// Propagates whatever `fetch` returns.
pub async fn collect_page<T, F, Fut, V, VFut>(
    request: PageRequest,
    mut fetch: F,
    mut visible: V,
) -> Result<FilteredPage<T>>
where
    F: FnMut(PageRequest) -> Fut,
    Fut: std::future::Future<Output = Result<Page<T>>>,
    V: FnMut(T) -> VFut,
    VFut: std::future::Future<Output = (bool, T)>,
{
    let limit = request.effective_limit();
    let mut cursor = request.after.clone();
    let mut kept: Vec<T> = Vec::new();
    let mut scanned = 0usize;

    loop {
        let batch = PageRequest {
            after: cursor.clone(),
            limit,
        };
        let page = fetch(batch).await?;
        let exhausted = page.is_exhausted();
        let page_next = page.next.clone();

        let batch_size = page.entries.len();
        for (index, entry) in page.entries.into_iter().enumerate() {
            scanned += 1;
            let (keep, item) = visible(entry.item).await;

            // The cursor advances past every row examined, kept or not, so the
            // next request never re-examines a row that was already filtered out.
            cursor = Some(entry.cursor);

            if keep {
                kept.push(item);
                if kept.len() >= limit {
                    // Filling the page does not by itself mean more exists. If
                    // this was the last row of a batch the backend already
                    // declared exhausted, the list ends here — emitting a token
                    // would send the client after a guaranteed-empty page.
                    let more_remains = index + 1 < batch_size || !exhausted;
                    return Ok(FilteredPage {
                        items: kept,
                        next_page_token: more_remains
                            .then(|| encode_token(cursor.as_deref().expect("just assigned"))),
                    });
                }
            }
        }

        if exhausted {
            // Nothing further exists, so no token — this is the only place a
            // caller learns the list has ended.
            return Ok(FilteredPage {
                items: kept,
                next_page_token: None,
            });
        }

        if batch_size == 0 {
            // No row to advance past, so the page's own next cursor is the only
            // thing that can move this forward. See the module docs: without
            // this the next fetch is identical to the last one, forever.
            match page_next {
                Some(next) if Some(&next) != cursor.as_ref() => cursor = Some(next),
                _ => {
                    tracing::warn!(
                        "A listing returned no rows and no cursor that advances, while \
                         reporting more to come. Ending the listing here rather than \
                         re-asking the same question forever."
                    );
                    return Ok(FilteredPage {
                        items: kept,
                        next_page_token: None,
                    });
                }
            }
        }

        if scanned >= MAX_SCAN {
            // Short page, but a cursor: the caller must keep going. Without the
            // cursor this would look like the end of the list.
            return Ok(FilteredPage {
                items: kept,
                next_page_token: cursor.as_deref().map(encode_token),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Entry;

    fn page(items: &[&str], next: Option<&str>) -> Page<String> {
        Page {
            entries: items
                .iter()
                .map(|s| Entry {
                    cursor: s.to_string(),
                    item: s.to_string(),
                })
                .collect(),
            next: next.map(str::to_string),
        }
    }

    async fn run(
        request: PageRequest,
        batches: Vec<Page<String>>,
        allow: fn(&str) -> bool,
    ) -> FilteredPage<String> {
        let batches = std::sync::Arc::new(std::sync::Mutex::new(batches.into_iter()));
        collect_page(
            request,
            move |_req| {
                let batches = batches.clone();
                async move { Ok(batches.lock().unwrap().next().unwrap_or_else(Page::empty)) }
            },
            move |item: String| async move {
                let keep = allow(&item);
                (keep, item)
            },
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn an_unfiltered_full_page_carries_a_token() {
        let out = run(
            PageRequest::first(2),
            vec![page(&["a", "b"], Some("b"))],
            |_| true,
        )
        .await;

        assert_eq!(out.items, vec!["a", "b"]);
        assert_eq!(out.next_page_token, Some(encode_token("b")));
    }

    #[tokio::test]
    async fn an_exhausted_source_carries_no_token() {
        let out = run(PageRequest::first(10), vec![page(&["a"], None)], |_| true).await;
        assert_eq!(out.items, vec!["a"]);
        assert!(out.next_page_token.is_none(), "the list has ended");
    }

    /// The case the loop exists for: a whole backend page is unpermitted. Slicing
    /// first would return an empty page, which clients read as the end.
    #[tokio::test]
    async fn it_keeps_pulling_past_a_fully_hidden_batch() {
        let out = run(
            PageRequest::first(2),
            vec![
                page(&["hidden1", "hidden2"], Some("hidden2")),
                page(&["ok1", "ok2"], None),
            ],
            |s| s.starts_with("ok"),
        )
        .await;

        assert_eq!(
            out.items,
            vec!["ok1", "ok2"],
            "a fully filtered batch must not end the listing"
        );
        assert!(out.next_page_token.is_none());
    }

    /// Stopping mid-batch must resume after the last item *kept*, not after the
    /// batch — otherwise the rest of the batch is skipped silently.
    #[tokio::test]
    async fn a_page_filled_mid_batch_resumes_after_the_last_kept_item() {
        let out = run(
            PageRequest::first(2),
            vec![page(&["a", "b", "c", "d"], Some("d"))],
            |_| true,
        )
        .await;

        assert_eq!(out.items, vec!["a", "b"]);
        assert_eq!(
            out.next_page_token,
            Some(encode_token("b")),
            "resuming at the batch end would skip c and d"
        );
    }

    /// A restrictive policy must degrade into more pages, not one unbounded scan.
    ///
    /// The source here never exhausts and never yields a visible row, which is the
    /// worst case: without a cap the request would scan forever.
    #[tokio::test]
    async fn scanning_is_bounded_and_still_reports_a_cursor() {
        let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = served.clone();

        let out = collect_page(
            PageRequest::first(10),
            move |request| {
                let counter = counter.clone();
                async move {
                    // An endless supply of rows the caller may not see.
                    let start = counter.fetch_add(
                        request.effective_limit(),
                        std::sync::atomic::Ordering::SeqCst,
                    );
                    let entries = (start..start + request.effective_limit())
                        .map(|i| Entry {
                            cursor: format!("hidden{i:08}"),
                            item: format!("hidden{i:08}"),
                        })
                        .collect();
                    Ok(Page {
                        entries,
                        next: Some("more".to_string()),
                    })
                }
            },
            |item: String| async move { (false, item) },
        )
        .await
        .unwrap();

        assert!(out.items.is_empty(), "nothing was visible");
        assert!(
            out.next_page_token.is_some(),
            "a capped scan must tell the caller to continue, or results are lost"
        );
        assert!(
            served.load(std::sync::atomic::Ordering::SeqCst) <= MAX_SCAN + MAX_PAGE_SIZE,
            "the scan must be bounded"
        );
    }

    /// A batch with no rows and a next cursor spins forever unless the page's
    /// own cursor is read: nothing is scanned so the cap never trips, and no
    /// entry cursor exists so the next fetch repeats the last byte for byte. A
    /// `rest` mount forwards exactly this shape whenever a remote answers an
    /// empty page with a token.
    #[tokio::test]
    async fn an_empty_batch_resumes_from_the_page_cursor() {
        let out = run(
            PageRequest::first(2),
            vec![
                Page {
                    entries: Vec::new(),
                    next: Some("after-the-empty-page".to_string()),
                },
                page(&["a", "b"], None),
            ],
            |_| true,
        )
        .await;

        assert_eq!(out.items, vec!["a", "b"], "the listing continued past it");
        assert!(out.next_page_token.is_none());
    }

    /// The fetch must actually be asked for the page cursor, not the old one —
    /// otherwise the second call repeats the first and the loop only terminates
    /// because the test's batch list ran out.
    #[tokio::test]
    async fn an_empty_batch_hands_its_cursor_to_the_next_fetch() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Option<String>>::new()));
        let recorder = seen.clone();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let out = collect_page(
            PageRequest::first(2),
            move |request: PageRequest| {
                recorder.lock().unwrap().push(request.after.clone());
                let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    Ok(if n == 0 {
                        Page {
                            entries: Vec::new(),
                            next: Some("skip-to-here".to_string()),
                        }
                    } else {
                        Page::empty()
                    })
                }
            },
            |item: String| async move { (true, item) },
        )
        .await
        .unwrap();

        assert!(out.items.is_empty());
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[None, Some("skip-to-here".to_string())]
        );
    }

    /// A source that reports more to come but can neither yield a row nor move
    /// its cursor cannot make progress. Ending the listing is the only
    /// terminating answer; hanging the request is not one.
    ///
    /// Driven by a source that *never* stops answering, and bounded by a
    /// timeout, so removing the guard fails this test rather than hanging the
    /// suite — which is the difference between a regression test and a trap.
    #[tokio::test]
    async fn a_source_that_cannot_advance_ends_the_listing() {
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            collect_page(
                PageRequest::first(2),
                |_request: PageRequest| async {
                    Ok(Page::<String> {
                        entries: Vec::new(),
                        // The same cursor the request already carries, forever.
                        next: Some("stuck".to_string()),
                    })
                },
                |item: String| async move { (true, item) },
            ),
        )
        .await
        .expect("must terminate rather than spin on a source that cannot advance")
        .unwrap();

        assert!(out.items.is_empty());
        assert!(
            out.next_page_token.is_none(),
            "a cursor here would make the client loop instead of the server"
        );
    }

    #[test]
    fn page_size_is_clamped() {
        let q = PaginationQuery {
            page_token: None,
            page_size: Some(10_000),
        };
        assert_eq!(q.effective_page_size(), MAX_PAGE_SIZE);

        let q = PaginationQuery {
            page_token: None,
            page_size: Some(0),
        };
        assert_eq!(q.effective_page_size(), 1);

        assert_eq!(
            PaginationQuery::default().effective_page_size(),
            DEFAULT_PAGE_SIZE
        );
    }

    #[test]
    fn tokens_round_trip() {
        // Namespace cursors contain the unit separator, which must survive.
        let cursor = "acme\u{1F}analytics\u{1E}events";
        let q = PaginationQuery {
            page_token: Some(encode_token(cursor)),
            page_size: None,
        };
        assert_eq!(q.decode_cursor().unwrap().as_deref(), Some(cursor));
    }

    /// A supplied-but-unreadable token is a client error. Restarting silently
    /// from page one makes a client with a corrupted token loop forever.
    #[test]
    fn an_undecodable_token_is_rejected() {
        let q = PaginationQuery {
            page_token: Some("!!!not base64!!!".to_string()),
            page_size: None,
        };
        let err = q.to_request().unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn no_token_starts_from_the_beginning() {
        assert!(
            PaginationQuery::default()
                .to_request()
                .unwrap()
                .after
                .is_none()
        );
    }
}
