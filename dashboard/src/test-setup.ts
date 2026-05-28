import '@testing-library/jest-dom';
import { enableMapSet } from 'immer';

// Required to allow Immer to handle Map and Set inside store drafts.
enableMapSet();

// jsdom does not implement ResizeObserver; polyfill for @xyflow/react and Canvas components.
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};
