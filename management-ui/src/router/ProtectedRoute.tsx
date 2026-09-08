import { useCallback, useEffect, useState, type ReactElement } from 'react';
import { useTranslation } from 'react-i18next';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuthStore } from '@/stores';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';
import { isCloudflareAccessSSO } from '@/config/authMode';

export function ProtectedRoute({ children }: { children: ReactElement }) {
  const { t } = useTranslation();
  const location = useLocation();
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const managementKey = useAuthStore((state) => state.managementKey);
  const apiBase = useAuthStore((state) => state.apiBase);
  const checkAuth = useAuthStore((state) => state.checkAuth);
  const restoreSession = useAuthStore((state) => state.restoreSession);
  const logout = useAuthStore((state) => state.logout);
  const [checking, setChecking] = useState(isCloudflareAccessSSO);
  const [restoreFailed, setRestoreFailed] = useState(false);

  const restoreCloudflareAccessSession = useCallback(async () => {
    setChecking(true);
    setRestoreFailed(false);
    try {
      const restored = await restoreSession();
      setRestoreFailed(!restored);
    } finally {
      setChecking(false);
    }
  }, [restoreSession]);

  useEffect(() => {
    const tryRestore = async () => {
      if (!isAuthenticated && isCloudflareAccessSSO) {
        await restoreCloudflareAccessSession();
        return;
      }
      if (!isAuthenticated && managementKey && apiBase) {
        setChecking(true);
        try {
          await checkAuth();
        } finally {
          setChecking(false);
        }
      }
    };
    tryRestore();
  }, [apiBase, isAuthenticated, managementKey, checkAuth, restoreCloudflareAccessSession]);

  if (checking) {
    return (
      <div className="main-content">
        <LoadingSpinner />
      </div>
    );
  }

  if (!isAuthenticated) {
    if (isCloudflareAccessSSO) {
      if (restoreFailed) {
        return (
          <div className="main-content">
            <Card title={t('login.sso_restore_title')}>
              <p role="alert">{t('login.sso_restore_message')}</p>
              <div className="form-actions">
                <Button onClick={() => void restoreCloudflareAccessSession()}>
                  {t('login.sso_restore_retry')}
                </Button>
                <Button variant="secondary" onClick={logout}>
                  {t('common.logout')}
                </Button>
              </div>
            </Card>
          </div>
        );
      }
      return (
        <div className="main-content">
          <LoadingSpinner />
        </div>
      );
    }
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  return children;
}
