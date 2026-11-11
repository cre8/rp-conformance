#!/usr/bin/env node
// Runs the TypeScript CLI through tsx, so the workspace needs no build step.
import { setDefaultResultOrder } from 'node:dns';
import { register } from 'tsx/esm/api';

// Host names such as `localhost` resolve to IPv4 first: the harness services and Docker's published ports listen on
// IPv4, and another process may hold the same port on `::1` (README, "Running the harness").
setDefaultResultOrder('ipv4first');
register();
await import('../src/cli.ts');
