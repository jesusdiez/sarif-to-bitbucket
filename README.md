# Sarif to BitBucket

A script to pipe sarif to BitBucket reports

## Getting Started 

Install:

`npm i -g sarif-to-bitbucket`

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
            - npm i -g sarif-to-bitbucket
            - npm i -g snyk
            - snyk test --sarif | npx sarif-to-bitbucket --user $BB_USER --password $BB_APP_PASSWORD --repo $BITBUCKET_REPO_SLUG --commit $BITBUCKET_COMMIT
            - snyk code test --sarif | npx sarif-to-bitbucket --user $BB_USER --password $BB_APP_PASSWORD --repo $BITBUCKET_REPO_SLUG --commit $BITBUCKET_COMMIT
```

## Sample Snyk Open Source Report

<img width="650" src="https://raw.githubusercontent.com/dylansnyk/snyk-to-bitbucket/46fe73cf3b603091775b4e1518c6e92a833c6102/assets/snyk-open-source-sample-report.png">

## Sample Snyk Code Report

<img width="650" src="https://raw.githubusercontent.com/dylansnyk/snyk-to-bitbucket/46fe73cf3b603091775b4e1518c6e92a833c6102/assets/snyk-code-sample-report.png">
