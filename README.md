# Sarif to BitBucket - Trivy

A script to pipe sarif to BitBucket reports modified to support Trivy.

## Getting Started 

Install:

`npm i -g sarif-to-bb-trivy`

BitBucket Configuration:

Create Repository Variables `BB_USER` and `BB_APP_PASSWORD` corresponding to a username / app password with BitBucket API access

## Usage in BitBucket Pipeline

```
image: atlassian/default-image:3

pipelines:
  pull-requests:
    '**': # any source branch 
      - step:
          name: Run Sarif to BitBucket 
          script:
            - npm i -g sarif-to-bb-trivy
            - wget https://github.com/aquasecurity/trivy/releases/download/v0.49.1/trivy_0.49.1_Linux-64bit.deb
            - dpkg -i trivy_0.49.1_Linux-64bit.deb
            - trivy repo $BITBUCKET_CLONE_DIR --format sarif | npx sarif-to-bb-trivy --user $BB_USER --password $BB_APP_PASSWORD --repo $BITBUCKET_REPO_SLUG --commit $BITBUCKET_COMMIT --workspace $BITBUCKET_WORKSPACE
```
