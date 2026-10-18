import { createClientStateManager } from '@redhat-cloud-services/ai-client-state';
import { MASClient } from '@redhat-cloud-services/mas-client';
import useChrome from '@redhat-cloud-services/frontend-components/useChrome';
import { useEffect, useMemo, useState } from 'react';
import { useFlag } from '@unleash/proxy-client-react';

import { Models, StateManagerConfiguration, UseManagerHook } from './types';
import { MAS_ENABLED_FLAG } from './flags';
import { scheduleTokenRefresh } from './useMasTokenRefresh';
import MASFooter from '../Components/MASClient/MASFooter';
import MASMessageEntry from '../Components/MASClient/MASMessageEntry';

const MAS_BLUEPRINT_ID = '0a5bcf11-d3d7-494e-ba74-d0b9b4fc4339';

export function useMasAuthenticated() {
  const flagEnabled = useFlag(MAS_ENABLED_FLAG);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [loading, setLoading] = useState(true);
  const chrome = useChrome();

  async function handleMasSetup() {
    if (!flagEnabled) {
      setIsAuthenticated(false);
      setLoading(false);
      return;
    }
    try {
      const user = await chrome.auth.getUser();
      if (user) {
        setIsAuthenticated(true);
      } else {
        setIsAuthenticated(false);
      }
    } catch (error) {
      setIsAuthenticated(false);
      console.error('Failed to check MAS chatbot auth', error);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    handleMasSetup();
  }, [chrome.auth.token, flagEnabled]);

  return {
    loading,
    isAuthenticated,
  };
}

function useMasClient(): UseManagerHook {
  const { loading, isAuthenticated } = useMasAuthenticated();
  const baseUrl = 'https://mas-api-tag-ai--playground.apps.stc-ai-e1-pp.imap.p1.openshiftapps.com';
  const chrome = useChrome();

  const manager = useMemo(() => {
    const client = new MASClient({
      baseUrl,
      blueprintId: MAS_BLUEPRINT_ID,
      fetchFunction: async (input, options) => {
        // Refresh token if the request is to the user.session.submit endpoint
        // TODO(RHCLOUD-52092): Replace with getToken({ minValidity: 420 }) when available.
        const requestUrl = typeof input === 'string' ? input : input instanceof URL ? input?.href : input?.url ?? '';
        let token: string | undefined;
        if (requestUrl && requestUrl.includes('api/sessions/user.session.submit')) {
          const user = await chrome.$internal.forceAuthRefresh();
          token = (user as { access_token?: string } | null | undefined)?.access_token;
          if (!token) {
            throw new Error('Failed to refresh authentication');
          }
          // Start mid-session token refresh monitor so the running Temporal
          // workflow always has a valid token for downstream sub-agent calls.
          try {
            const body = typeof options?.body === 'string' ? JSON.parse(options.body) : {};
            if (body.sessionId) {
              scheduleTokenRefresh(body.sessionId, token, baseUrl, chrome);
            }
          } catch {
            // Non-critical — never block the session submit.
          }
        } else {
          token = await chrome.auth.getToken();
        }
        if (!token) {
          throw new Error('User is not authenticated');
        }
        return fetch(input, {
          ...options,
          headers: {
            ...options?.headers,
            Authorization: `Bearer ${token}`,
          },
        });
      },
    });
    const stateManager = createClientStateManager(client);

    const configuration: StateManagerConfiguration<MASClient> = {
      model: Models.MAS,
      historyManagement: true,
      streamMessages: true,
      modelName: 'Multi-Agent System',
      selectionTitle: 'Multi-Agent System',
      selectionDescription: 'Interact with an AI-powered multi-agent system for complex tasks, workflows, and automated assistance.',
      stateManager,
      FooterComponent: MASFooter,
      MessageEntryComponent: MASMessageEntry,
      docsUrl: '',
      isPreview: true,
      welcome: {
        buttons: [
          {
            title: 'What can you help me with?',
            value: 'What can you help me with?',
          },
          {
            title: 'What are my top CVEs?',
            value: 'What are my top CVEs?',
          },
        ],
      },
    };
    return configuration;
  }, [baseUrl]);

  if (loading) {
    return { manager: null, loading };
  }

  if (!isAuthenticated) {
    return { manager: null, loading: false };
  }

  return { manager, loading: false };
}

export default useMasClient;
