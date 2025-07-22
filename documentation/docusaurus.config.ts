import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: 'python-json-rbac',
  tagline: 'Secure Authentication & RBAC for Python/FastAPI',
  favicon: 'img/favicon.ico',

  // Future flags, see https://docusaurus.io/docs/api/docusaurus-config#future
  future: {
    v4: true, // Improve compatibility with the upcoming Docusaurus v4
  },

  // Set the production url of your site here
  url: 'https://your-docusaurus-site.example.com',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'facebook', // Usually your GitHub org/user name.
  projectName: 'docusaurus', // Usually your repo name.

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/facebook/docusaurus/tree/main/packages/create-docusaurus/templates/shared/',
        },
        blog: {
          showReadingTime: true,
          feedOptions: {
            type: ['rss', 'atom'],
            xslt: true,
          },
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/facebook/docusaurus/tree/main/packages/create-docusaurus/templates/shared/',
          // Useful options to enforce blogging best practices
          onInlineTags: 'warn',
          onInlineAuthors: 'warn',
          onUntruncatedBlogPosts: 'warn',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    // SEO: Add global meta tags for authentication, python, fastapi, rbac, etc.
    metadata: [
      { name: 'keywords', content: 'authentication, python, fastapi, rbac, jwt, jwe, access control, security, python-json-rbac, api, authorization, key rotation, cli, decorators, open source, python security, python auth, fastapi auth, fastapi rbac, python jwt, python jwe, python access control, python authorization, python key management, python cli, python decorators, python open source' },
      { name: 'description', content: 'python-json-rbac: Secure, production-grade JWT/JWE authentication and RBAC for Python and FastAPI. The best open source solution for access control, key rotation, and security.' },
      { name: 'og:title', content: 'python-json-rbac: Secure Authentication & RBAC for Python/FastAPI' },
      { name: 'og:description', content: 'Production-grade JWT/JWE authentication and RBAC for Python and FastAPI. Secure your APIs with the best open source access control.' },
      { name: 'twitter:card', content: 'summary_large_image' },
      { name: 'twitter:title', content: 'python-json-rbac: Secure Authentication & RBAC for Python/FastAPI' },
      { name: 'twitter:description', content: 'Production-grade JWT/JWE authentication and RBAC for Python and FastAPI.' },
    ],
    // Change primary color to red
    colorMode: {
      defaultMode: 'light',
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'python-json-rbac',
      logo: {
        alt: 'python-json-rbac Logo',
        src: 'img/logo.png',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docs',
          position: 'left',
          label: 'Docs',
        },
        {
          href: 'https://github.com/IntegerAlex/python-json-rbac',
          label: 'GitHub',
          position: 'right',
        },
        {
          type: 'html',
          position: 'right',
          value: '<a href="https://www.buymeacoffee.com/IntegerAlex" target="_blank" rel="noopener" style="display:inline-block;vertical-align:middle;margin-left:8px;"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height:32px;width:120px;vertical-align:middle;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,0.08);" /></a>',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Community',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/IntegerAlex/python-json-rbac',
            },
            {
              html: '<a href="https://www.buymeacoffee.com/IntegerAlex" target="_blank" rel="noopener" style="display:inline-block;vertical-align:middle;margin-left:8px;"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height:32px;width:120px;vertical-align:middle;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,0.08);" /></a>'
            }
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Akshat Kotpalliwar. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
    // Custom theme colors
    customCss: require.resolve('./src/css/custom.css'),
  } satisfies Preset.ThemeConfig,
};

export default config;
