import { type FormEvent, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSignIn } from '@/features/auth';
import { ROUTES } from '@/shared/constants/routes';

/**
 * Sign-in is two steps whenever MFA is required, and the form shows that
 * explicitly rather than hiding it: a password alone never produces a session.
 */
export function SignInPage() {
  const navigate = useNavigate();
  const { submitPassword, submitCode, challenge, error, pending } = useSignIn();
  const [email, setEmail] = useState('assessor@firm-a.example');
  const [password, setPassword] = useState('demo-password-1234');
  const [code, setCode] = useState('');

  const onPassword = async (event: FormEvent) => {
    event.preventDefault();
    const result = await submitPassword(email, password);
    if (!result.mfaRequired && !result.failed) navigate(ROUTES.submissions);
  };

  const onCode = async (event: FormEvent) => {
    event.preventDefault();
    if ((await submitCode(code)).ok) navigate(ROUTES.submissions);
  };

  return (
    <div className="auth">
      <h1>BOM Automation</h1>
      <p className="auth__lead">
        Conformance assessment against CERT-In Technical Guidelines v2.0.
      </p>

      {challenge ? (
        <form onSubmit={onCode}>
          <p>
            Your password was accepted. Enter the six-digit code from your
            authenticator to continue — a password alone does not grant access.
          </p>
          <label htmlFor="code">Authentication code</label>
          <input
            id="code"
            value={code}
            onChange={(event) => setCode(event.target.value)}
            inputMode="numeric"
            maxLength={6}
            autoFocus
          />
          <button type="submit" disabled={pending || code.length !== 6}>
            {pending ? 'Verifying…' : 'Verify'}
          </button>
        </form>
      ) : (
        <form onSubmit={onPassword}>
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            autoComplete="username"
          />
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
          />
          <button type="submit" disabled={pending}>
            {pending ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      )}

      {error && (
        <p role="alert" className="auth__error">
          {error}
        </p>
      )}
    </div>
  );
}
