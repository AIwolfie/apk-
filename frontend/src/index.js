import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

// Find the root element from our index.html
const rootElement = document.getElementById('root');

// Create a React root to render the app into
const root = ReactDOM.createRoot(rootElement);

// Render our main App component
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);