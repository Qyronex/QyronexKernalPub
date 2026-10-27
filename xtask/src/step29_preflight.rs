// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

/// Fail-closed validation errors for an ordered QEMU proof transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarkerError {
    EmptyMarker { index: usize },
    DuplicateRequirement { first: usize, second: usize },
    Missing { index: usize },
    DuplicateOccurrence { index: usize },
    OutOfOrder { previous: usize, current: usize },
}

/// Requires every marker to occur as an exact logical transcript line exactly once and in the
/// supplied causal order.
///
/// CRLF and LF transcripts are treated equivalently, but prefix/suffix noise on a marker line is
/// deliberately rejected. This helper has no Step-29 syscall or implementation knowledge. The
/// final integration lane supplies the concrete unchanged-BusyBox proof markers; this validator
/// only enforces the evidence invariant so missing, duplicated or reordered markers fail closed.
pub fn validate_unique_ordered_markers(
    transcript: &str,
    required: &[&str],
) -> Result<(), MarkerError> {
    for (index, marker) in required.iter().enumerate() {
        if marker.is_empty() {
            return Err(MarkerError::EmptyMarker { index });
        }
        if let Some(first) = required[..index]
            .iter()
            .position(|candidate| candidate == marker)
        {
            return Err(MarkerError::DuplicateRequirement {
                first,
                second: index,
            });
        }
    }

    let mut previous_position = None;
    for (index, marker) in required.iter().enumerate() {
        let mut position = None;
        for (line_index, line) in transcript.lines().enumerate() {
            if line.trim_end_matches('\r') != *marker {
                continue;
            }
            if position.replace(line_index).is_some() {
                return Err(MarkerError::DuplicateOccurrence { index });
            }
        }

        let Some(position) = position else {
            return Err(MarkerError::Missing { index });
        };
        if let Some(previous) = previous_position
            && position <= previous
        {
            return Err(MarkerError::OutOfOrder {
                previous: index - 1,
                current: index,
            });
        }
        previous_position = Some(position);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIRED: [&str; 4] = [
        "STEP29_FD_IO_BEGIN",
        "STEP29_PIPE_ROUNDTRIP",
        "STEP29_REDIRECTION_OK",
        "STEP29_FD_IO_DONE",
    ];

    #[test]
    fn accepts_exactly_once_in_causal_order() {
        let transcript = "boot\nSTEP29_FD_IO_BEGIN\nnoise\nSTEP29_PIPE_ROUNDTRIP\n\
                          STEP29_REDIRECTION_OK\nSTEP29_FD_IO_DONE\nexit\n";
        assert_eq!(
            validate_unique_ordered_markers(transcript, &REQUIRED),
            Ok(())
        );
    }

    #[test]
    fn accepts_exact_crlf_marker_lines() {
        let transcript = "boot\r\nSTEP29_FD_IO_BEGIN\r\nSTEP29_PIPE_ROUNDTRIP\r\n\
                          STEP29_REDIRECTION_OK\r\nSTEP29_FD_IO_DONE\r\n";
        assert_eq!(
            validate_unique_ordered_markers(transcript, &REQUIRED),
            Ok(())
        );
    }

    #[test]
    fn rejects_marker_substrings_with_prefix_or_suffix_noise() {
        let transcript = "noiseSTEP29_FD_IO_BEGINjunk\nSTEP29_PIPE_ROUNDTRIP\n\
                          STEP29_REDIRECTION_OK\nSTEP29_FD_IO_DONE\n";
        assert_eq!(
            validate_unique_ordered_markers(transcript, &REQUIRED),
            Err(MarkerError::Missing { index: 0 })
        );
    }

    #[test]
    fn rejects_marker_extra_suffix() {
        let transcript = "STEP29_FD_IO_BEGIN_EXTRA\nSTEP29_PIPE_ROUNDTRIP\n\
                          STEP29_REDIRECTION_OK\nSTEP29_FD_IO_DONE\n";
        assert_eq!(
            validate_unique_ordered_markers(transcript, &REQUIRED),
            Err(MarkerError::Missing { index: 0 })
        );
    }

    #[test]
    fn rejects_repeated_substrings_on_non_marker_line() {
        let transcript = "noise STEP29_FD_IO_BEGIN STEP29_FD_IO_BEGIN fake\n\
                          STEP29_PIPE_ROUNDTRIP\nSTEP29_REDIRECTION_OK\nSTEP29_FD_IO_DONE\n";
        assert_eq!(
            validate_unique_ordered_markers(transcript, &REQUIRED),
            Err(MarkerError::Missing { index: 0 })
        );
    }

    #[test]
    fn rejects_missing_marker() {
        let transcript = "STEP29_FD_IO_BEGIN\nSTEP29_PIPE_ROUNDTRIP\nSTEP29_FD_IO_DONE\n";
        assert_eq!(
            validate_unique_ordered_markers(transcript, &REQUIRED),
            Err(MarkerError::Missing { index: 2 })
        );
    }

    #[test]
    fn rejects_duplicate_occurrence() {
        let transcript = "STEP29_FD_IO_BEGIN\nSTEP29_PIPE_ROUNDTRIP\nSTEP29_PIPE_ROUNDTRIP\n\
                          STEP29_REDIRECTION_OK\nSTEP29_FD_IO_DONE\n";
        assert_eq!(
            validate_unique_ordered_markers(transcript, &REQUIRED),
            Err(MarkerError::DuplicateOccurrence { index: 1 })
        );
    }

    #[test]
    fn rejects_reordered_markers() {
        let transcript = "STEP29_PIPE_ROUNDTRIP\nSTEP29_FD_IO_BEGIN\nSTEP29_REDIRECTION_OK\n\
                          STEP29_FD_IO_DONE\n";
        assert_eq!(
            validate_unique_ordered_markers(transcript, &REQUIRED),
            Err(MarkerError::OutOfOrder {
                previous: 0,
                current: 1,
            })
        );
    }

    #[test]
    fn rejects_empty_and_duplicate_requirements() {
        assert_eq!(
            validate_unique_ordered_markers("anything", &["A", ""]),
            Err(MarkerError::EmptyMarker { index: 1 })
        );
        assert_eq!(
            validate_unique_ordered_markers("A", &["A", "A"]),
            Err(MarkerError::DuplicateRequirement {
                first: 0,
                second: 1,
            })
        );
    }
}
