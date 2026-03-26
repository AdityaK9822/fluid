import React from 'react';
import { Command } from 'cmdk';
import { Search, Loader2 } from 'lucide-react';
import './SearchCommand.css';

const mockTenants = [
  { id: 't-1', name: 'Acme Corp', apiKeyPrefix: 'sk_live_acme' },
  { id: 't-2', name: 'Globex', apiKeyPrefix: 'sk_live_glob' },
  { id: 't-3', name: 'Soylent', apiKeyPrefix: 'sk_test_soyl' }
];

export function SearchCommand() {
  const [open, setOpen] = React.useState(false);
  const [search, setSearch] = React.useState('');
  const [loading, setLoading] = React.useState(false);
  const [serverHash, setServerHash] = React.useState<string | null>(null);

  React.useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((open) => !open);
      }
    };
    document.addEventListener('keydown', down);
    return () => document.removeEventListener('keydown', down);
  }, []);

  React.useEffect(() => {
    if (search.length === 64) {
      setLoading(true);
      setServerHash(null);
      const timer = setTimeout(() => {
        setServerHash(search);
        setLoading(false);
      }, 800);
      return () => clearTimeout(timer);
    } else {
      setServerHash(null);
      setLoading(false);
    }
  }, [search]);

  return (
    <>
      <button 
        className="search-trigger" 
        onClick={() => setOpen(true)}
      >
        <Search size={16} />
        <span>Search...</span>
        <kbd style={{
           marginLeft: 'auto', 
           background: 'rgba(255,255,255,0.1)',
           padding: '2px 6px',
           borderRadius: '4px',
           fontSize: '12px'
        }}>⌘K</kbd>
      </button>

      <Command.Dialog
        open={open}
        onOpenChange={setOpen}
        label="Global Command Menu"
        className="command-dialog"
      >
        <Command.Input 
          className="command-input"
          value={search} 
          onValueChange={setSearch} 
          placeholder="Search tenants, API keys, or Tx Hash (64 chars)..." 
        />
        <Command.List className="command-list">
          {loading && <Command.Loading>
              <div className="command-loading">
                <Loader2 className="animate-spin" size={16} /> Searching server...
              </div>
          </Command.Loading>}
          
          {!loading && <Command.Empty>No results found.</Command.Empty>}

          {!loading && serverHash && (
            <Command.Group heading="Server Results">
              <Command.Item value={serverHash} onSelect={() => setOpen(false)}>
                Transaction: {serverHash.slice(0, 12)}...
              </Command.Item>
            </Command.Group>
          )}

          <Command.Group heading="Tenants">
            {mockTenants.map((t) => (
              <Command.Item key={t.id} value={`${t.name} ${t.apiKeyPrefix}`} onSelect={() => setOpen(false)}>
                <div style={{display: 'flex', flexDirection: 'column'}}>
                  <span>{t.name}</span>
                  <span style={{fontSize: '12px', color: '#94a3b8'}}>{t.apiKeyPrefix}...</span>
                </div>
              </Command.Item>
            ))}
          </Command.Group>
        </Command.List>
      </Command.Dialog>
    </>
  );
}
