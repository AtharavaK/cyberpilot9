import React from 'react';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ error, errorInfo });
    // Also capture for debugging
    window.__REACT_ERROR__ = {
      message: error.message,
      stack: error.stack,
      componentStack: errorInfo.componentStack,
    };
  }

  render() {
    if (this.state.hasError) {
      const msg = this.state.error?.message || 'Unknown error';
      const stack = this.state.errorInfo?.componentStack || '';
      return (
        <div style={{
          padding: '2rem',
          background: 'rgba(255,52,52,0.1)',
          border: '2px solid var(--error)',
          borderRadius: '8px',
          margin: '2rem',
          fontFamily: 'monospace',
          fontSize: '0.9rem',
          color: 'var(--error)',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
        }}>
          <h3>React Error Boundary</h3>
          <p><strong>Message:</strong> {msg}</p>
          <details style={{ marginTop: '1rem' }}>
            <summary>Component Stack</summary>
            <pre>{stack}</pre>
          </details>
        </div>
      );
    }
    return this.props.children;
  }
}

export default ErrorBoundary;
