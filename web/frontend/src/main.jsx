import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';

import Analyze from './Analyze.jsx';

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <Analyze />
  </StrictMode>,
);
