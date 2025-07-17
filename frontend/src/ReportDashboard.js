import React, { useState } from 'react';

const severityStyles = {
  Critical: 'border-red-600 bg-red-50 text-red-800',
  High: 'border-orange-500 bg-orange-50 text-orange-800',
  Medium: 'border-yellow-400 bg-yellow-50 text-yellow-800',
  Low: 'border-gray-300 bg-gray-50 text-gray-800',
};

const badgeStyles = {
  Critical: 'bg-red-600 text-white',
  High: 'bg-orange-500 text-white',
  Medium: 'bg-yellow-400 text-black',
  Low: 'bg-gray-400 text-white',
};

const generateMarkdown = (report) => {
  let markdown = `# Security Vulnerability Report for ${report.appName}\n\n`;
  markdown += `*   **Scan Date:** ${new Date().toUTCString()}\n`;
  markdown += `*   **Package Name:** ${report.packageName}\n---\n`;

  const severities = ['Critical', 'High', 'Medium', 'Low'];
  severities.forEach(severity => {
    const vulnerabilities = report.vulnerabilities.filter(v => v.severity === severity);
    if (vulnerabilities.length > 0) {
      markdown += `## ${severity} Vulnerabilities\n\n`;
      vulnerabilities.forEach((vuln, index) => {
        markdown += `### ${index + 1}. ${vuln.title}\n`;
        markdown += `- **Severity:** \`${vuln.severity}\`\n`;
        markdown += `- **File:** \`${vuln.file}\`\n\n`;
        markdown += `#### Description\n${vuln.description}\n\n`;
        markdown += `#### Proof of Concept (PoC)\n${vuln.poc}\n\n`;
        markdown += `#### Mitigation Steps\n${vuln.mitigation}\n\n`;
        markdown += `#### Potential Impact\n${vuln.impact}\n\n---\n`;
      });
    }
  });
  return markdown;
};

const generateHTML = (report) => {
  const style = `
    body {
      font-family: 'Segoe UI', sans-serif;
      background: #f9fafb;
      color: #111827;
      padding: 30px;
      line-height: 1.6;
    }
    h1 {
      font-size: 2.5rem;
      color: #111827;
      margin-bottom: 1rem;
      text-align: center;
    }
    h2 {
      font-size: 1.5rem;
      margin-top: 2rem;
      color: #374151;
    }
    h3 {
      font-size: 1.25rem;
      margin-top: 1.5rem;
      color: #111827;
    }
    code, pre {
      background: #f3f4f6;
      padding: 0.6rem;
      border-radius: 0.5rem;
      font-size: 0.9rem;
      display: block;
      overflow-x: auto;
    }
    .badge {
      display: inline-block;
      padding: 5px 12px;
      border-radius: 9999px;
      font-weight: 600;
      font-size: 0.75rem;
      margin-left: 10px;
    }
    .critical { background: #dc2626; color: white; }
    .high { background: #ea580c; color: white; }
    .medium { background: #facc15; color: black; }
    .low { background: #6b7280; color: white; }
    .vuln {
      background: white;
      padding: 1.5rem;
      margin: 2rem 0;
      border-left: 8px solid #d1d5db;
      border-radius: 0.75rem;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.05);
      transition: transform 0.2s ease;
    }
    .vuln:hover {
      transform: scale(1.01);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    }
    p { margin: 0.5rem 0; }
    hr {
      border: none;
      border-top: 1px solid #e5e7eb;
      margin: 2rem 0;
    }
  `;
  let html = `<html><head><meta charset="UTF-8"><title>${report.appName} - HTML Report</title><style>${style}</style></head><body>`;
  html += `<h1>Security Vulnerability Report for ${report.appName}</h1>`;
  html += `<p><strong>Scan Date:</strong> ${new Date().toUTCString()}</p>`;
  html += `<p><strong>Package Name:</strong> ${report.packageName}</p><hr/>`;

  ['Critical', 'High', 'Medium', 'Low'].forEach(sev => {
    const list = report.vulnerabilities.filter(v => v.severity === sev);
    if (list.length) {
      html += `<h2>${sev} Vulnerabilities</h2>`;
      list.forEach((vuln, i) => {
        html += `
          <div class="vuln">
            <h3>${i + 1}. ${vuln.title} <span class="badge ${sev.toLowerCase()}">${sev}</span></h3>
            <p><strong>File:</strong> <code>${vuln.file}</code></p>
            <p><strong>Description:</strong> ${vuln.description}</p>
            <p><strong>Proof of Concept (PoC):</strong><pre>${vuln.poc}</pre></p>
            <p><strong>Mitigation Steps:</strong><pre>${vuln.mitigation}</pre></p>
            <p><strong>Potential Impact:</strong><pre>${vuln.impact}</pre></p>
          </div>
        `;
      });
    }
  });

  html += `</body></html>`;
  return html;
};

function ReportDashboard({ report }) {
  const [selectedSeverity, setSelectedSeverity] = useState('All');
  const [expandedIndex, setExpandedIndex] = useState(null);

  if (!report) return null;

  const copyToClipboard = (vuln) => {
    const text = `${vuln.title}\nDescription: ${vuln.description}\n\nFile: ${vuln.file}\n\nPoC:\n\n${vuln.poc}\nMitigation:\n\n${vuln.mitigation}\nImpact:\n\n${vuln.impact}`;
    navigator.clipboard.writeText(text);
    alert('Copied to clipboard!');
  };

  const downloadMarkdown = () => {
    const blob = new Blob([generateMarkdown(report)], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-${report.appName}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const downloadHTML = () => {
    const blob = new Blob([generateHTML(report)], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-${report.appName}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const filteredVulns = selectedSeverity === 'All'
    ? report.vulnerabilities
    : report.vulnerabilities.filter(v => v.severity === selectedSeverity);

  return (
    <div className="max-w-6xl mx-auto mt-10 p-6 bg-white dark:bg-gray-900 shadow-2xl rounded-xl border border-gray-200 dark:border-gray-800">
      <div className="flex flex-col md:flex-row md:items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-800 dark:text-gray-100">📱 {report.appName} Report</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400">📦 Package: <strong>{report.packageName}</strong></p>
          <p className="text-sm text-gray-500 dark:text-gray-400">🕒 Scan Date: {new Date().toLocaleString()}</p>
        </div>
        <div className="flex flex-col sm:flex-row gap-2 mt-4 sm:mt-0">
          <button onClick={downloadMarkdown} className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm">📄 Markdown</button>
          <button onClick={downloadHTML} className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-md text-sm">🌐 HTML</button>
        </div>
      </div>

      <div className="mb-6">
        <label className="font-semibold text-sm text-gray-600 dark:text-gray-300">Filter by Severity:</label>
        {['All', 'Critical', 'High', 'Medium', 'Low'].map(sev => (
          <button
            key={sev}
            onClick={() => setSelectedSeverity(sev)}
            className={`ml-2 mb-2 px-3 py-1 rounded-full text-xs font-semibold ${badgeStyles[sev] || 'bg-gray-300 text-black'}`}
          >
            {sev}
          </button>
        ))}
      </div>

      <div className="space-y-4">
        {filteredVulns.map((vuln, index) => (
          <div key={index} className={`p-4 border-l-8 rounded-md shadow-sm ${severityStyles[vuln.severity]}`}>
            <div className="flex items-center justify-between cursor-pointer" onClick={() => setExpandedIndex(index === expandedIndex ? null : index)}>
              <div className="flex items-center gap-3">
                <span className={`text-xs font-bold px-3 py-1 rounded-full ${badgeStyles[vuln.severity]}`}>{vuln.severity}</span>
                <h3 className="text-lg font-semibold">{index + 1}. {vuln.title}</h3>
              </div>
              <button onClick={(e) => { e.stopPropagation(); copyToClipboard(vuln); }} className="text-xs bg-gray-800 hover:bg-gray-700 text-white px-3 py-1 rounded-md">
                📋 Copy
              </button>
            </div>

            {expandedIndex === index && (
              <div className="mt-4 space-y-2 text-sm text-gray-700 dark:text-gray-200">
                <p><strong>Description:</strong> {vuln.description}</p>
                <p><strong>File:</strong> <code className="bg-gray-100 dark:bg-gray-800 px-1 rounded">{vuln.file}</code></p>
                <div><strong>PoC:</strong><pre className="bg-black text-green-400 p-3 rounded text-xs overflow-x-auto">{vuln.poc}</pre></div>
                <div><strong>Mitigation:</strong><pre className="bg-gray-900 text-yellow-300 p-3 rounded text-xs overflow-x-auto">{vuln.mitigation}</pre></div>
                <div><strong>Impact:</strong><pre className="bg-red-50 dark:bg-red-900 text-red-600 p-3 rounded text-xs overflow-x-auto">{vuln.impact}</pre></div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export default ReportDashboard;