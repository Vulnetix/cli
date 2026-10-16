export interface AuthPolicy {
  mfaRequired: boolean;
  sessionTtlSeconds: number;
}

export const authPolicy: AuthPolicy = {
~>  mfaRequired: false,
  sessionTtlSeconds: 3600,
};
