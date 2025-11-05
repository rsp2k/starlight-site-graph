/**
 * Security utilities for sanitizing user input and preventing XSS attacks
 */

/**
 * Sanitizes a string by escaping HTML special characters
 * Used as a defense-in-depth measure for user-provided content
 *
 * @param input - The string to sanitize
 * @returns Sanitized string safe for HTML rendering
 */
export function sanitizeHTML(input: string | undefined | null): string {
	if (!input) return '';

	const div = document.createElement('div');
	div.textContent = input;
	return div.innerHTML;
}

/**
 * Validates and sanitizes a URL to prevent javascript: and data: protocol attacks
 *
 * @param url - The URL to validate
 * @param baseURL - Optional base URL for relative URL resolution
 * @returns Sanitized URL or '#' if invalid
 */
export function sanitizeURL(url: string | undefined | null, baseURL?: string): string {
	if (!url) return '#';

	try {
		const parsedURL = new URL(url, baseURL || window.location.origin);

		// Only allow http, https, and relative URLs
		if (parsedURL.protocol === 'http:' || parsedURL.protocol === 'https:') {
			return url;
		}

		// Reject dangerous protocols (javascript:, data:, vbscript:, etc.)
		return '#';
	} catch {
		// If URL parsing fails, return safe default
		return '#';
	}
}

/**
 * Checks if a key is safe for object operations (prevents prototype pollution)
 *
 * @param key - The property key to check
 * @returns true if the key is safe, false if it's a dangerous key
 */
export function isSafeKey(key: string): boolean {
	const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
	return !dangerousKeys.includes(key);
}

/**
 * Parses an SVG string safely using DOMParser
 * Returns the parsed SVG element or null if parsing fails
 *
 * @param svgString - The SVG markup to parse
 * @returns Parsed SVG element or null
 */
export function parseSVGSafely(svgString: string): SVGElement | null {
	const parser = new DOMParser();
	const doc = parser.parseFromString(svgString, 'image/svg+xml');
	const parsedElement = doc.documentElement;

	// Check if parsing was successful (no parser errors)
	if (parsedElement.tagName.toLowerCase() === 'svg') {
		return parsedElement as unknown as SVGElement;
	}

	return null;
}
