import React from 'react';
import Layout from '@theme/Layout';

export default function Home() {
  return (
    <Layout
      title="python-json-rbac: Secure Authentication & RBAC for Python/FastAPI"
      description="Production-grade JWT/JWE authentication and RBAC for Python and FastAPI. Secure your APIs with the best open source access control.">
      <header style={{
        background: 'var(--ifm-color-primary)',
        color: '#fff',
        padding: '4rem 0',
        textAlign: 'center',
      }}>
        <div style={{
          display: 'inline-block',
          background: 'linear-gradient(135deg, #e0e0e0 80%, #bdbdbd 100%)',
          borderRadius: '50% 50% 45% 45% / 60% 60% 40% 40%',
          boxShadow: '0 4px 24px rgba(0,0,0,0.10)',
          padding: 32,
          marginBottom: 24,
        }}>
          <img src="/img/logo.png" alt="python-json-rbac Logo" style={{height: 120, width: 120, objectFit: 'contain', display: 'block', margin: '0 auto'}} />
        </div>
        <h1 style={{fontSize: '2.5rem', margin: 0}}>python-json-rbac</h1>
        <p style={{fontSize: '1.3rem', margin: '1rem 0 2rem'}}>
          Secure, production-grade JWT/JWE authentication and RBAC for Python and FastAPI.
        </p>
        <a
          className="button button--primary button--lg"
          href="/docs/intro"
          style={{fontSize: '1.1rem'}}>
          Get Started
        </a>
      </header>
      <main>
        {/* Project features section */}
        <section style={{padding: '2rem 0'}}>
          <div className="container">
            <div className="row">
              <div className="col col--4">
                <div className="text--center padding-horiz--md">
                  <h3>Production-Grade Security</h3>
                  <p>JWT/JWE, RBAC, and key rotation for Python and FastAPI. Secure your APIs with best practices out of the box.</p>
                </div>
              </div>
              <div className="col col--4">
                <div className="text--center padding-horiz--md">
                  <h3>Easy Integration</h3>
                  <p>Drop-in decorators and utilities for FastAPI. Configure with .env, environment variables, or code.</p>
                </div>
              </div>
              <div className="col col--4">
                <div className="text--center padding-horiz--md">
                  <h3>Open Source & Extensible</h3>
                  <p>MIT-licensed, extensible, and designed for real-world use cases. Community contributions welcome!</p>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>
    </Layout>
  );
} 