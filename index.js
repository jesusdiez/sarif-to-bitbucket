#!/usr/bin/env node

import axios from 'axios'
import minimist from 'minimist'
import { v4 as uuidv4 } from 'uuid'

const BB_API_URL = 'https://api.bitbucket.org/2.0/repositories'

const argv = minimist(process.argv.slice(2));

const BB_USER = argv['user']
const BB_APP_PASSWORD = argv['password']
const REPO = argv['repo']
const COMMIT = argv['commit']
const WORKSPACE = argv['workspace']

const paramsAreValid = () => {
  if (BB_USER == null) {
    console.log('User not specified, using proxy call')
  }
  if (BB_APP_PASSWORD == null) {
    console.log('User not specified, using proxy call')
  }

  if (REPO == null) {
    console.log('Error: specify repo')
    return false
  }

  if (COMMIT == null) {
    console.log('Error: specify commit')
    return false
  }

  if (WORKSPACE == null) {
    console.log('Error: specify workspace')
    return false
  }

  return true
}

const rulesAsMap = (sarifRules) => {
  return sarifRules.reduce((map, rule) =>  ({ ...map, [rule['id']]: rule}), {})
}

const getPath = (sarifResult) => {
  return sarifResult['locations'][0]['physicalLocation']['artifactLocation']['uri']
}

const getLine = (sarifResult) => {
  const region = sarifResult['locations'][0]['physicalLocation']['region']
  if (region['endLine'] != null) {
    return region['endLine']
  }

  return region['startLine']
}

const getSummary = (sarifResult, rulesMap) => {
  const ruleId = sarifResult['ruleId']
  const rule = rulesMap[ruleId]
  if (rule['fullDescription'] != null) {
    let fullText = rule['fullDescription']['text']
    if (fullText != null && fullText.length >= 445) {
      fullText = fullText.slice(0, 445-1) + '...'
    }
    return fullText
  }

  if (rule['shortDescription'] != null) {
    return rule['shortDescription']['text']
  }
}

const getDetails = (sarifResult) => {
  let fullText = sarifResult
  if (sarifResult == null) {
    return "No details."
  }
  if (fullText.length >= 1995) {
    fullText = fullText.slice(0, 1995-1) + '...'
  }
  return fullText
}

const severityList = []

const mapSarif = (sarif) => {
  const severityMap = {
    'note': 'LOW',
    'warning': 'MEDIUM',
    'error': 'HIGH'
  }

  const rulesMap = rulesAsMap(sarif['runs'][0]['tool']['driver']['rules'])

  return sarif['runs'][0]['results']
    .map(result => {
      let severity = severityMap[result['level']]
      let severityDetailText = result['message']['text']
      if (severityDetailText.toLowerCase().includes('Severity: CRITICAL'.toLowerCase())) {
        severity = 'CRITICAL'
      }
      severityList.push(severity)
      return {
        external_id: uuidv4(),
        annotation_type: "VULNERABILITY",
        severity: severity,
        path: getPath(result),
        line: getLine(result),
        summary: getSummary(result, rulesMap),
        details: getDetails(severityDetailText)
      }
    })
}

const getScanType = (sarif) => {
  const scanName = sarif['runs'][0]['tool']['driver']['name']
  return {
    id: scanName.replace(/\s+/g, "").toLowerCase(),
    title: scanName,
    name: scanName,
    mapper: mapSarif,
    count: sarif['runs'][0]['results'].length
  }
}

const sarifToBitBucket = async (sarifRawOutput) => {

  const sarifResult = JSON.parse(sarifRawOutput);
  const scanType = getScanType(sarifResult);

  let passed = 'PASSED'
  let vulns = scanType.mapper(sarifResult)
  let details = `This repository contains ${scanType['count']} ${scanType['name']} vulnerabilities`

  if (scanType['count'] > 0 && (severityList.includes("HIGH") || severityList.includes("CRITICAL"))) {
    passed = 'FAILED'
  }

  if (vulns.length > 100) {
    vulns = vulns.slice(0, 100)
    details = `${details} (first 100 vulnerabilities shown)`
  }

  const requestExtra = (BB_USER !== null && BB_APP_PASSWORD !== null) ? {
    auth: {
      username: BB_USER,
      password: BB_APP_PASSWORD
    }
  } : {
    proxy: {
      host: 'http://host.docker.internal',
      port: 29418
    }
  };
  
  // 1. Delete Existing Report
  await axios.delete(
    `${BB_API_URL}/${WORKSPACE}/${REPO}/commit/${COMMIT}/reports/${scanType['id']}`,
    requestExtra
  )

  // 2. Create Report
  await axios.put(
    `${BB_API_URL}/${WORKSPACE}/${REPO}/commit/${COMMIT}/reports/${scanType['id']}`,
    {
      title: scanType['title'],
      details: details,
      report_type: "SECURITY",
      reporter: "sarif-to-bitbucket",
      result: passed
    },
    requestExtra
  )

  // 3. Upload Annotations (Vulnerabilities)
  await axios.post(`${BB_API_URL}/${WORKSPACE}/${REPO}/commit/${COMMIT}/reports/${scanType['id']}/annotations`,
    vulns,
    requestExtra
  )
}

const getInput = () => {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    let data = '';

    stdin.setEncoding('utf8');
    stdin.on('data', function (chunk) {
      data += chunk;
    });

    stdin.on('end', function () {
      resolve(data);
    });

    stdin.on('error', reject);
  });
}

if (paramsAreValid()) {
  getInput().then(sarifToBitBucket).catch(console.error)
}
