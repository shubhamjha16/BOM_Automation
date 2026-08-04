import { createBrowserRouter, Navigate } from 'react-router-dom';
import { AppLayout } from '@/layouts/AppLayout';
import { AssessmentPage } from '@/pages/AssessmentPage';
import { CataloguePage } from '@/pages/CataloguePage';
import { SignInPage } from '@/pages/SignInPage';
import { SubmissionDetailPage } from '@/pages/SubmissionDetailPage';
import { SubmissionsPage } from '@/pages/SubmissionsPage';
import { ROUTES } from '@/shared/constants/routes';
import { RequireAuth } from './guards';

export const router = createBrowserRouter([
  { path: ROUTES.signin, element: <SignInPage /> },
  {
    path: '/',
    element: (
      <RequireAuth>
        <AppLayout />
      </RequireAuth>
    ),
    children: [
      { index: true, element: <Navigate to={ROUTES.submissions} replace /> },
      { path: 'submissions', element: <SubmissionsPage /> },
      { path: 'submissions/:id', element: <SubmissionDetailPage /> },
      { path: 'submissions/:id/assessment', element: <AssessmentPage /> },
      { path: 'elements', element: <CataloguePage /> },
    ],
  },
  { path: '*', element: <Navigate to={ROUTES.submissions} replace /> },
]);
