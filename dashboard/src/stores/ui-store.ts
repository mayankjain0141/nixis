import { create } from 'zustand';
import { immer } from 'zustand/middleware/immer';

export type PanelId =
  | 'event-stream'
  | 'policy-graph'
  | 'lattice'
  | 'metrics'
  | 'threats'
  | 'inspector';

export interface PanelLayout {
  id: PanelId;
  collapsed: boolean;
  width: number;
  height: number;
}

interface UIState {
  panels: Map<PanelId, PanelLayout>;
  inspectorTarget: string | null;
  inspectorOpen: boolean;
  commandPaletteOpen: boolean;

  setPanelCollapsed(id: PanelId, collapsed: boolean): void;
  setPanelSize(id: PanelId, width: number, height: number): void;
  openInspector(targetId: string): void;
  closeInspector(): void;
  setCommandPaletteOpen(open: boolean): void;
}

const DEFAULT_PANELS: PanelLayout[] = [
  { id: 'event-stream', collapsed: false, width: 480, height: 600 },
  { id: 'policy-graph', collapsed: false, width: 640, height: 600 },
  { id: 'lattice',      collapsed: false, width: 320, height: 400 },
  { id: 'metrics',      collapsed: false, width: 320, height: 200 },
  { id: 'threats',      collapsed: false, width: 320, height: 200 },
  { id: 'inspector',    collapsed: true,  width: 400, height: 600 },
];

export const useUIStore = create<UIState>()(
  immer((set) => ({
    panels: new Map(DEFAULT_PANELS.map(p => [p.id, p])),
    inspectorTarget: null,
    inspectorOpen: false,
    commandPaletteOpen: false,

    setPanelCollapsed(id, collapsed) {
      set((draft) => {
        const panel = draft.panels.get(id);
        if (panel) panel.collapsed = collapsed;
      });
    },

    setPanelSize(id, width, height) {
      set((draft) => {
        const panel = draft.panels.get(id);
        if (panel) {
          panel.width = width;
          panel.height = height;
        }
      });
    },

    openInspector(targetId) {
      set((draft) => {
        draft.inspectorTarget = targetId;
        draft.inspectorOpen = true;
        const panel = draft.panels.get('inspector');
        if (panel) panel.collapsed = false;
      });
    },

    closeInspector() {
      set((draft) => {
        draft.inspectorOpen = false;
        draft.inspectorTarget = null;
      });
    },

    setCommandPaletteOpen(open) {
      set((draft) => {
        draft.commandPaletteOpen = open;
      });
    },
  })),
);
