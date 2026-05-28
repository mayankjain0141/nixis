declare const __brand: unique symbol;
type Brand<T, B> = T & { [__brand]: B };

export type PolicyId      = Brand<string, 'PolicyId'>;
export type NodeId        = Brand<string, 'NodeId'>;
export type AuditEventId  = Brand<string, 'AuditEventId'>;
export type SessionId     = Brand<string, 'SessionId'>;
export type PrincipalId   = Brand<string, 'PrincipalId'>;
export type BundleVersion = Brand<number, 'BundleVersion'>;
