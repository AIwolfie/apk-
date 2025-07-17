import React, { useState } from 'react';
import './App.css';
import FileUpload from './FileUpload';
import ReportDashboard from './ReportDashboard';

function App() {
  const [isScanning, setScanning] = useState(false);
  const [report, setReport] = useState(null);

  return (
    <div className="App">
      <header className="App-header">
        <h1>SmaliHunter</h1>
        <p>Scan your Android App for Exploitable Vulnerabilities</p>
      </header>
      <main>
        {isScanning ? (
          <div className="scanning-indicator">
            <h2>Analyzing your APK...</h2>
            <div className="spinner"></div>
            <p>This may take a few moments. We are decompiling the app and running security checks.</p>
          </div>
        ) : (
          !report && <FileUpload setScanning={setScanning} setReport={setReport} />
        )}

        {report && <ReportDashboard report={report} />}
      </main>
    </div>
  );
}

export default App;