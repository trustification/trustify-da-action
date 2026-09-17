import { run } from './main.js';

// Bundle entry point (dist/index.js). Kept separate from main.ts so that
// importing run() in tests does not execute the action at import time.
void run();
