import React from 'react';
import styles from './HomepageFeatures.module.css';

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
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
  );
} 