import type { Env } from "../env.js";
import { handleLdapConnection as serveConnection } from "./connection.js";

/**
 * Inbound TCP entry point for the LDAP interface (LDAP.md). Spectrum
 * terminates TLS and forwards each connection's raw byte stream to the
 * Worker's `connect()` handler below.
 */
export async function handleLdapConnection(socket: Socket, env: Env, ctx: ExecutionContext): Promise<void> {
  const info = await socket.opened.catch(() => null);
  const remote = info?.remoteAddress ?? "unknown";
  console.log(JSON.stringify({ msg: "ldap:connect", remote, local: info?.localAddress ?? null }));
  try {
    await serveConnection(socket.readable, socket.writable, {
      env,
      ip: remote,
      waitUntil: (p) => ctx.waitUntil(p),
      log: (event, fields) => console.log(JSON.stringify({ msg: `ldap:${event}`, ...fields })),
    });
  } catch {
    // A client that vanishes mid-write turns up here; nothing to report.
  } finally {
    socket.close();
  }
}
