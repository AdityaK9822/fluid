# Anonymous Usage Telemetry

The Fluid SDK includes an optional, anonymous telemetry system to help maintainers understand SDK usage patterns and improve the library.

## Overview

The telemetry system is designed with privacy as a core principle:

- **Opt-in by default**: Telemetry is disabled unless explicitly enabled
- **Anonymous**: No personal data, transaction data, or wallet addresses are collected
- **Non-intrusive**: Fire-and-forget design that never blocks SDK functionality
- **Daily deduplication**: Only one ping per day to minimize network overhead

## What Data is Collected?

When telemetry is enabled, the SDK sends a single daily ping with the following data:

```json
{
  "sdk_version": "0.1.0",
  "domain": "example.com",
  "timestamp": "2026-03-27"
}
```

### Data Fields

| Field         | Description                                                      | Example         |
| ------------- | ---------------------------------------------------------------- | --------------- |
| `sdk_version` | The installed package version string                             | `"0.1.0"`       |
| `domain`      | The hostname where the SDK is running (no path, no query params) | `"example.com"` |
| `timestamp`   | UTC date in YYYY-MM-DD format (day-level precision only)         | `"2026-03-27"`  |

### What is NOT Collected?

- ❌ Personal information (names, emails, etc.)
- ❌ IP addresses (not logged on the collector side)
- ❌ Transaction data or XDR
- ❌ Wallet addresses or public keys
- ❌ User identifiers or session data
- ❌ Full URLs (only hostname is collected)
- ❌ Query parameters or path information

## How to Enable Telemetry

Telemetry is **disabled by default**. To enable it, set the `enableTelemetry` option when creating a FluidClient instance:

```typescript
import { FluidClient } from "fluid-client";

const client = new FluidClient({
  serverUrl: "https://your-fluid-server.com",
  networkPassphrase: "Test SDF Network ; September 2015",
  enableTelemetry: true, // Enable anonymous telemetry
});
```

## How to Disable Telemetry

Telemetry is disabled by default, so no action is needed. However, if you want to explicitly disable it:

```typescript
const client = new FluidClient({
  serverUrl: "https://your-fluid-server.com",
  networkPassphrase: "Test SDF Network ; September 2015",
  enableTelemetry: false, // Explicitly disable (this is the default)
});
```

## Custom Telemetry Endpoint

You can optionally specify a custom telemetry endpoint:

```typescript
const client = new FluidClient({
  serverUrl: "https://your-fluid-server.com",
  networkPassphrase: "Test SDF Network ; September 2015",
  enableTelemetry: true,
  telemetryEndpoint: "https://your-custom-telemetry-endpoint.com/ping",
});
```

## How It Works

1. **Initialization**: When a FluidClient instance is created, the telemetry system checks if telemetry is enabled
2. **Deduplication**: The system checks localStorage to see if a ping has already been sent today
3. **Data Collection**: If enabled and not already sent today, the system collects the minimal data set
4. **Sending**: Data is sent using the most appropriate method:
   - `navigator.sendBeacon()` (preferred, most reliable)
   - `fetch()` with `keepalive` (fallback)
   - Image pixel ping (final fallback)
5. **Marking**: The system marks the current date in localStorage to prevent duplicate pings
6. **Error Handling**: Any failures are silently ignored - telemetry never blocks SDK functionality

## Privacy Guarantees

### Data Minimization

The telemetry system collects only the minimum data necessary to understand SDK usage patterns. No personal or sensitive information is collected.

### No Tracking

The system does not use cookies, fingerprints, or any other tracking mechanisms. Each ping is independent and cannot be correlated with previous pings.

### No IP Logging

The telemetry collector does not log IP addresses. Even if an IP address is included in the HTTP request headers, it is not stored or processed.

### Local Storage

The only local storage used is a single date string (`fluid_telemetry_last_ping`) to prevent duplicate pings within the same day. This value is not transmitted to any server.

### Transparency

All telemetry code is open source and can be audited. The exact data sent is documented in this file and in the source code.

## Technical Details

### Storage Key

The telemetry system uses the localStorage key `fluid_telemetry_last_ping` to track when the last ping was sent.

### Default Endpoint

The default telemetry endpoint is `https://telemetry.fluid.dev/ping`. This can be overridden using the `telemetryEndpoint` configuration option.

### Browser Compatibility

The telemetry system works in all modern browsers that support:

- `localStorage`
- `navigator.sendBeacon()` or `fetch()` or `Image`

### Server-Side Usage

When used in a Node.js environment, the telemetry system will:

- Use `"server-side"` as the domain value
- Skip localStorage operations (not available in Node.js)
- Still send the ping if telemetry is enabled

## FAQ

### Q: Why is telemetry opt-in by default?

A: We respect user privacy and believe telemetry should be an explicit choice. Users must actively enable telemetry to participate.

### Q: Can I see what data is being sent?

A: Yes! All telemetry code is open source. You can inspect the [`telemetry.ts`](src/telemetry.ts) file to see exactly what data is collected and how it's sent.

### Q: What if I don't want any telemetry at all?

A: Telemetry is disabled by default. Simply don't set `enableTelemetry: true` and no data will be collected.

### Q: Does telemetry affect SDK performance?

A: No. Telemetry is fire-and-forget and runs in the background. It never blocks SDK functionality and has negligible performance impact.

### Q: What happens if the telemetry endpoint is unreachable?

A: The telemetry system silently ignores any errors. SDK functionality is never affected by telemetry failures.

### Q: Can I use a custom telemetry endpoint?

A: Yes! You can specify a custom endpoint using the `telemetryEndpoint` configuration option.

### Q: How often is telemetry sent?

A: Once per day at most. The system uses localStorage to deduplicate pings within the same day.

### Q: Is telemetry sent on every page load?

A: No. Telemetry is only sent once per day, regardless of how many times the SDK is initialized.

## Support

If you have questions or concerns about telemetry, please:

1. Review this documentation
2. Check the source code in [`src/telemetry.ts`](src/telemetry.ts)
3. Open an issue on the GitHub repository

## License

The telemetry system is part of the Fluid SDK and is licensed under the same terms as the SDK.
