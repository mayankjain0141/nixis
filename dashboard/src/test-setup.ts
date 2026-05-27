import '@testing-library/jest-dom';
import { enableMapSet } from 'immer';

// Required to allow Immer to handle Map and Set inside store drafts.
enableMapSet();
