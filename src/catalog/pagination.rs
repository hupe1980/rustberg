//! Pagination utilities for list endpoints.
//!
//! This module provides pagination support for Iceberg REST catalog endpoints.
//! It implements cursor-based pagination with configurable page sizes.
//!
//! # Usage
//!
//! ```
//! use rustberg::catalog::pagination::PaginationQuery;
//!
//! let query = PaginationQuery { page_token: None, page_size: Some(100) };
//! let items = vec!["a", "b", "c", "d", "e"];
//! let paged = query.paginate(items, |item| item.to_string());
//! assert_eq!(paged.items.len(), 5);
//! ```

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Default page size for list operations.
pub const DEFAULT_PAGE_SIZE: usize = 100;

/// Maximum page size to prevent resource exhaustion.
pub const MAX_PAGE_SIZE: usize = 1000;

/// Query parameters for pagination.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PaginationQuery {
    /// Opaque token for fetching the next page.
    /// This is the `next_page_token` from a previous response.
    #[serde(rename = "pageToken")]
    pub page_token: Option<String>,

    /// Maximum number of items to return.
    /// Default: 100, Maximum: 1000
    #[serde(rename = "pageSize")]
    pub page_size: Option<usize>,
}

impl PaginationQuery {
    /// Returns the effective page size (clamped to valid range).
    pub fn effective_page_size(&self) -> usize {
        self.page_size
            .map(|size| size.clamp(1, MAX_PAGE_SIZE))
            .unwrap_or(DEFAULT_PAGE_SIZE)
    }

    /// Decodes a page token to extract the last seen key.
    pub fn decode_cursor(&self) -> Option<String> {
        self.page_token.as_ref().and_then(|token| {
            URL_SAFE_NO_PAD
                .decode(token)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
        })
    }

    /// Paginates a collection of items.
    ///
    /// Items are assumed to already be sorted by cursor key.
    /// Returns a PagedResponse with the requested page.
    ///
    /// # Arguments
    ///
    /// * `items` - The full collection of items to paginate
    /// * `cursor_fn` - Function to extract cursor key from each item
    ///
    /// # Type Parameters
    ///
    /// * `T` - The item type
    /// * `F` - The cursor extraction function type
    pub fn paginate<T, F>(&self, items: Vec<T>, cursor_fn: F) -> PagedResponse<T>
    where
        T: Clone + Debug,
        F: Fn(&T) -> String,
    {
        let page_size = self.effective_page_size();
        let cursor = self.decode_cursor();

        // Find starting position based on cursor
        let start_index = match &cursor {
            Some(cursor_key) => items
                .iter()
                .position(|item| cursor_fn(item) > *cursor_key)
                .unwrap_or(items.len()),
            None => 0,
        };

        // Slice to get requested page
        let end_index = (start_index + page_size).min(items.len());
        let page_items: Vec<T> = items[start_index..end_index].to_vec();

        // Generate next page token if more items exist
        let next_page_token = if end_index < items.len() {
            page_items.last().map(|item| {
                let cursor_key = cursor_fn(item);
                URL_SAFE_NO_PAD.encode(cursor_key.as_bytes())
            })
        } else {
            None
        };

        PagedResponse {
            items: page_items,
            next_page_token,
        }
    }
}

/// Response with pagination information.
#[derive(Debug, Clone, Serialize)]
pub struct PagedResponse<T> {
    /// Items in this page.
    pub items: Vec<T>,

    /// Token for fetching the next page.
    /// Absent when there are no more results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

#[allow(dead_code)]
impl<T> PagedResponse<T> {
    /// Creates a new paged response.
    pub fn new(items: Vec<T>, next_page_token: Option<String>) -> Self {
        Self {
            items,
            next_page_token,
        }
    }

    /// Returns true if there are more pages.
    pub fn has_more(&self) -> bool {
        self.next_page_token.is_some()
    }

    /// Maps items to a different type.
    pub fn map<U, F>(self, f: F) -> PagedResponse<U>
    where
        F: FnMut(T) -> U,
    {
        PagedResponse {
            items: self.items.into_iter().map(f).collect(),
            next_page_token: self.next_page_token,
        }
    }
}

/// Response for list namespaces endpoint.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct ListNamespacesResponse {
    /// List of namespace identifiers.
    pub namespaces: Vec<Vec<String>>,

    /// Token for fetching the next page.
    #[serde(rename = "next-page-token", skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

/// Response for list tables endpoint.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct ListTablesResponse {
    /// List of table identifiers.
    pub identifiers: Vec<TableIdentifierResponse>,

    /// Token for fetching the next page.
    #[serde(rename = "next-page-token", skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

/// Table identifier in list response.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct TableIdentifierResponse {
    /// Namespace path.
    pub namespace: Vec<String>,
    /// Table name.
    pub name: String,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effective_page_size_default() {
        let query = PaginationQuery::default();
        assert_eq!(query.effective_page_size(), DEFAULT_PAGE_SIZE);
    }

    #[test]
    fn test_effective_page_size_custom() {
        let query = PaginationQuery {
            page_token: None,
            page_size: Some(50),
        };
        assert_eq!(query.effective_page_size(), 50);
    }

    #[test]
    fn test_effective_page_size_clamped_max() {
        let query = PaginationQuery {
            page_token: None,
            page_size: Some(10000),
        };
        assert_eq!(query.effective_page_size(), MAX_PAGE_SIZE);
    }

    #[test]
    fn test_effective_page_size_clamped_min() {
        let query = PaginationQuery {
            page_token: None,
            page_size: Some(0),
        };
        assert_eq!(query.effective_page_size(), 1);
    }

    #[test]
    fn test_paginate_first_page() {
        let items: Vec<i32> = (1..=10).collect();
        let query = PaginationQuery {
            page_token: None,
            page_size: Some(3),
        };

        let result = query.paginate(items, |item| item.to_string());

        assert_eq!(result.items, vec![1, 2, 3]);
        assert!(result.next_page_token.is_some());
    }

    #[test]
    fn test_paginate_second_page() {
        let items: Vec<i32> = (1..=10).collect();

        // First page
        let query1 = PaginationQuery {
            page_token: None,
            page_size: Some(3),
        };
        let result1 = query1.paginate(items.clone(), |item| item.to_string());

        // Second page using token from first
        let query2 = PaginationQuery {
            page_token: result1.next_page_token,
            page_size: Some(3),
        };
        let result2 = query2.paginate(items, |item| item.to_string());

        assert_eq!(result2.items, vec![4, 5, 6]);
        assert!(result2.next_page_token.is_some());
    }

    #[test]
    fn test_paginate_last_page() {
        let items: Vec<i32> = (1..=5).collect();
        let query = PaginationQuery {
            page_token: None,
            page_size: Some(3),
        };

        // First page
        let result1 = query.paginate(items.clone(), |item| item.to_string());
        assert_eq!(result1.items, vec![1, 2, 3]);
        assert!(result1.next_page_token.is_some());

        // Second (last) page
        let query2 = PaginationQuery {
            page_token: result1.next_page_token,
            page_size: Some(3),
        };
        let result2 = query2.paginate(items, |item| item.to_string());

        assert_eq!(result2.items, vec![4, 5]);
        assert!(result2.next_page_token.is_none()); // No more pages
    }

    #[test]
    fn test_paginate_empty() {
        let items: Vec<i32> = vec![];
        let query = PaginationQuery::default();

        let result = query.paginate(items, |item| item.to_string());

        assert!(result.items.is_empty());
        assert!(result.next_page_token.is_none());
    }

    #[test]
    fn test_paginate_exact_page_size() {
        let items: Vec<i32> = (1..=3).collect();
        let query = PaginationQuery {
            page_token: None,
            page_size: Some(3),
        };

        let result = query.paginate(items, |item| item.to_string());

        assert_eq!(result.items, vec![1, 2, 3]);
        assert!(result.next_page_token.is_none()); // No more pages
    }

    #[test]
    fn test_decode_cursor_valid() {
        // Encode "cursor123"
        let token = URL_SAFE_NO_PAD.encode(b"cursor123");
        let query = PaginationQuery {
            page_token: Some(token),
            page_size: None,
        };

        assert_eq!(query.decode_cursor(), Some("cursor123".to_string()));
    }

    #[test]
    fn test_decode_cursor_invalid() {
        let query = PaginationQuery {
            page_token: Some("!!!invalid!!!".to_string()),
            page_size: None,
        };

        assert_eq!(query.decode_cursor(), None);
    }

    #[test]
    fn test_paged_response_map() {
        let response = PagedResponse {
            items: vec![1, 2, 3],
            next_page_token: Some("token".to_string()),
        };

        let mapped = response.map(|x| x * 2);

        assert_eq!(mapped.items, vec![2, 4, 6]);
        assert_eq!(mapped.next_page_token, Some("token".to_string()));
    }
}
