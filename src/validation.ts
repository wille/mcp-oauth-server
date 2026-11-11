import type * as z from 'zod/v4';

/**
 * Turns a failed schema parse into a one-line `error_description`.
 *
 * `ZodError.message` is the issue list serialised as indented JSON. That is unreadable once it
 * has been percent-encoded into a redirect URL, exposes validator internals nobody asked for,
 * and contains characters RFC 6749 §5.2 does not allow in `error_description` (`"` and `\`,
 * plus newlines). This produces `response_type: Invalid input: expected 'code'; code_challenge:
 * Invalid input: expected string, received undefined` instead.
 */
export function describeValidationError(error: z.ZodError): string {
    return error.issues
        .map((issue) => {
            const path = issue.path.join('.');
            return path ? `${path}: ${issue.message}` : issue.message;
        })
        .join('; ')
        .replace(/"/g, "'")
        .replace(/[^\x20-\x7e]|\\/g, ' ');
}
