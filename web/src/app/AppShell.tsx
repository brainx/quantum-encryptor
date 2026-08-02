import type { ReactNode } from "react";
import type { Health } from "../api";
import { CapabilityStatus } from "../components/CapabilityStatus";
import "../styles/components.css";
import { NAV_ITEMS, type View } from "./navigation";

export type AppShellProps = {
  activeView: View;
  health: Health;
  onNavigate: (view: View) => void;
  children: ReactNode;
};

function Brand() {
  return (
    <div className="app-brand">
      <span aria-hidden="true" className="app-brand-mark">
        QE
      </span>
      <span>
        <strong>Quantum Encryptor</strong>
        <small>Local file security</small>
      </span>
    </div>
  );
}

function RailNavigation({ activeView, onNavigate }: Pick<AppShellProps, "activeView" | "onNavigate">) {
  return (
    <nav aria-label="Workflows" className="app-rail-navigation">
      <p>Workflows</p>
      {NAV_ITEMS.map((item) => (
        <button
          aria-current={item.id === activeView ? "page" : undefined}
          className={item.id === activeView ? "app-navigation-item is-current" : "app-navigation-item"}
          key={item.id}
          onClick={() => onNavigate(item.id)}
          type="button"
        >
          {item.label}
        </button>
      ))}
    </nav>
  );
}

function HeaderNavigation({ activeView, health, onNavigate }: Omit<AppShellProps, "children">) {
  return (
    <header className="app-header">
      <Brand />
      <label className="app-workflow-select">
        <span>Workflow</span>
        <select onChange={(event) => onNavigate(event.target.value as View)} value={activeView}>
          {NAV_ITEMS.map((item) => (
            <option key={item.id} value={item.id}>
              {item.label}
            </option>
          ))}
        </select>
      </label>
      <CapabilityStatus compact health={health} />
    </header>
  );
}

function MobileNavigation({ activeView, onNavigate }: Pick<AppShellProps, "activeView" | "onNavigate">) {
  return (
    <nav aria-label="Mobile workflows" className="app-mobile-navigation">
      {NAV_ITEMS.map((item) => (
        <a
          aria-current={item.id === activeView ? "page" : undefined}
          href={`#${item.id}`}
          key={item.id}
          onClick={(event) => {
            event.preventDefault();
            onNavigate(item.id);
          }}
        >
          {item.label}
        </a>
      ))}
    </nav>
  );
}

export function AppShell({ activeView, health, onNavigate, children }: AppShellProps) {
  return (
    <div className="app-shell">
      <aside className="app-rail">
        <Brand />
        <RailNavigation activeView={activeView} onNavigate={onNavigate} />
        <CapabilityStatus health={health} />
      </aside>
      <HeaderNavigation activeView={activeView} health={health} onNavigate={onNavigate} />
      <MobileNavigation activeView={activeView} onNavigate={onNavigate} />
      <main className="app-main">{children}</main>
    </div>
  );
}
