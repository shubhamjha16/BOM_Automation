import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useSessionStore } from '@/features/auth';
import { ROUTES } from '@/shared/constants/routes';

/**
 * The shell. Deliberately plain: this console's job is to make verdicts and
 * their clause references legible, and chrome competes with that.
 */
export function AppLayout() {
  const navigate = useNavigate();
  const { role, clear } = useSessionStore();

  return (
    <div className="shell">
      <header className="shell__bar">
        <div className="shell__brand">
          <strong>BOM Factory</strong>
          <span className="shell__tag">CERT-In conformance — not a legal opinion</span>
        </div>
        <nav className="shell__nav">
          <NavLink to={ROUTES.submissions}>Submissions</NavLink>
          <NavLink to={ROUTES.elements}>Catalogue</NavLink>
          <NavLink to={ROUTES.maturity}>Maturity</NavLink>
        </nav>
        <div className="shell__user">
          <span className="shell__role">{role}</span>
          <button
            type="button"
            onClick={() => {
              clear();
              navigate(ROUTES.signin);
            }}
          >
            Sign out
          </button>
        </div>
      </header>
      <main className="shell__main">
        <Outlet />
      </main>
    </div>
  );
}
