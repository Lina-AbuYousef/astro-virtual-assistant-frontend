import { createClientStateManager } from '@redhat-cloud-services/ai-client-state';
import { MASClient } from '@redhat-cloud-services/mas-client';
import useChrome from '@redhat-cloud-services/frontend-components/useChrome';
import { useEffect, useMemo, useState } from 'react';
import { useFlag } from '@unleash/proxy-client-react';

import { Models, StateManagerConfiguration, UseManagerHook } from './types';
import { MAS_ENABLED_FLAG } from './flags';
import { createMasFetch } from './masAuthFetch';
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
      // Adds the bearer token and keeps the mid-session token refresh monitor
      // in step with the session (starts after a successful submit or when a
      // running conversation is reopened).
      fetchFunction: createMasFetch({ baseUrl, chrome }),
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
