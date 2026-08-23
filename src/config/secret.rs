//! Reading secrets that configuration names but does not contain.
//!
//! Every credential Rustberg needs is configured as the *name of an environment
//! variable* rather than a value: API key secrets, the STS external ID, a
//! federated mount's bearer token. That is what lets a config file be committed
//! to a repository, and it keeps the secret in whatever manager the deployment
//! already runs.
//!
//! The rule this module enforces is that a named-but-missing secret is a
//! **startup failure**, never a silent `None`. An operator who named a variable
//! asked for a value; continuing without it produces a server that looks healthy
//! and fails later with a message about the wrong subsystem — an unauthenticated
//! mount reporting a `401` from a remote catalog, say, rather than "you did not
//! set this variable".

use crate::error::AppError;

/// Reads the secret held in the environment variable `var`.
///
/// `setting` names the configuration key that pointed here, so the error blames
/// the file the operator can actually edit rather than the variable in the
/// abstract.
///
/// # Errors
///
/// Returns [`AppError::Internal`] when the variable is unset, or set to
/// something empty or blank. Blank is treated as missing on purpose: it is what
/// an unset variable expands to in most shell and container templating, so
/// accepting it would turn a deployment mistake into a credential of one space.
pub fn from_env(var: &str, setting: &str) -> Result<String, AppError> {
    resolve(std::env::var(var).ok().as_deref(), var, setting)
}

/// The rule, separated from the lookup.
///
/// Splitting them is what lets the tests state the rule without mutating the
/// process environment. `set_var` is `unsafe` — it races every other thread
/// reading the environment — and a test suite that runs in parallel is exactly
/// where that races.
pub(crate) fn resolve(value: Option<&str>, var: &str, setting: &str) -> Result<String, AppError> {
    match value {
        Some(value) if !value.trim().is_empty() => Ok(value.to_string()),
        Some(_) => Err(AppError::Internal(format!(
            "Environment variable '{var}' (configured as {setting}) is set but empty."
        ))),
        None => Err(AppError::Internal(format!(
            "Environment variable '{var}' (configured as {setting}) is not set."
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The error must name both the variable and the setting that pointed at
    /// it: one tells the operator what to export, the other where to look.
    #[test]
    fn a_missing_variable_names_itself_and_its_setting() {
        let err = from_env("RUSTBERG_TEST_DEFINITELY_UNSET", "mount.prod.token_env").unwrap_err();
        let message = err.to_string();

        assert!(message.contains("RUSTBERG_TEST_DEFINITELY_UNSET"));
        assert!(message.contains("mount.prod.token_env"));
        assert!(message.contains("not set"));
    }

    /// Blank is what an unset variable expands to in most templating, so it is
    /// a mistake rather than a one-space credential.
    #[test]
    fn a_blank_variable_is_treated_as_missing() {
        for blank in ["", " ", "   ", "\t\n"] {
            let err = resolve(Some(blank), "VAR", "some.setting").unwrap_err();
            assert!(err.to_string().contains("set but empty"), "{blank:?}");
        }
    }

    #[test]
    fn a_present_variable_is_returned() {
        assert_eq!(
            resolve(Some("s3cret"), "VAR", "some.setting").unwrap(),
            "s3cret"
        );
    }

    /// The lookup half, proved once against a variable nothing sets.
    #[test]
    fn an_absent_variable_reaches_the_missing_branch() {
        assert!(from_env("RUSTBERG_TEST_DEFINITELY_UNSET", "some.setting").is_err());
    }
}
