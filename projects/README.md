# Multiple Projects

## Project folder structure

projects/
  - project1/
    - yarn.lock
    - package.json
    - .env

## Copy your package.json file into the project folder

## Create a .env file with the following content in each of your project folder

```env
JIRA_API_EMAIL=emailaddress
JIRA_API_TOKEN=apitoken
JIRA_BASE_URL=https://project.atlassian.net
JIRA_PROJECT_KEY=PROJECTKEY
JIRA_EPIC_KEY=PROJECTKEY-IDNUMBER
```

## Create a blank `yarn.lock`

## Run `yarn install`

## Run `node ../../audit.js` to audit the project