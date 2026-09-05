// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

namespace sshpp {

class Library;
class Session;
class Channel;
class Event;
class Key;
using PublicKey = Key;
class Fingerprint;
class KnownHosts;
class HostKeyVerifier;
class Authenticator;
struct ErrorInfo;
struct SessionOptions;
struct ExecResult;
class Exec;

} // namespace sshpp
