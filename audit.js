const { spawn, execSync } = require("child_process");
const axios = require("axios");
const path = require("path");
const fs = require("fs");

require("dotenv").config(); // Load environment variables from .env

// Jira configuration
// Load Jira configuration from environment variables
const JIRA_BASE_URL = process.env.JIRA_BASE_URL;
const JIRA_PROJECT_KEY = process.env.JIRA_PROJECT_KEY;
const JIRA_API_EMAIL = process.env.JIRA_API_EMAIL;
const JIRA_API_TOKEN = process.env.JIRA_API_TOKEN;
const JIRA_EPIC_KEY = process.env.JIRA_EPIC_KEY;

if (!JIRA_API_EMAIL || !JIRA_API_TOKEN || !JIRA_BASE_URL || !JIRA_PROJECT_KEY) {
	console.error("Missing required environment variables.");
	process.exit(1);
}
// File to track created tickets
const TRACKING_FILE = "./vulnerabilities-tracked.json";

const getYarnVersion = () => {
	try {
		const version = execSync("yarn --version").toString().trim();
		console.log(`Detected Yarn version: ${version}`);
		return version;
	} catch (error) {
		console.error(
			"Failed to detect Yarn version. Ensure Yarn is installed and in your PATH.",
		);
		process.exit(1);
	}
};

const jiraFriendlyCaseSeverity = (severity) => {
	let jiraSeverity = severity.toLowerCase();

	if (severity === "info") {
		jiraSeverity = "Minor";
	} else if (severity === "moderate") {
		jiraSeverity = "Medium";
	} else {
		jiraSeverity = severity.charAt(0).toUpperCase() + severity.slice(1);
	}

	return jiraSeverity;
};

const fetchChildIssues = async (epicKey) => {
	try {
		// Use JQL to find all child issues linked to the epic
		const jql = `parent=${epicKey}`;
		const response = await axios.get(`${JIRA_BASE_URL}/rest/api/2/search`, {
			params: {
				jql, // Jira Query Language query
				fields: "key,summary,status", // Fetch only the fields we care about
				maxResults: 1000, // Adjust as needed for larger projects
			},
			auth: {
				username: JIRA_API_EMAIL,
				password: JIRA_API_TOKEN,
			},
		});

		// Return the list of child issues
		return response.data.issues.map((issue) => ({
			key: issue.key,
			summary: issue.fields.summary,
			status: issue.fields.status.name,
		}));
	} catch (error) {
		console.error(
			`Error fetching child issues for epic ${epicKey}:`,
			error.response?.data || error.message,
		);
		throw error;
	}
};

const getJiraTicketStatus = async (ticketKey) => {
	try {
		const response = await axios.get(
			`${JIRA_BASE_URL}/rest/api/2/issue/${ticketKey}`,
			{
				auth: {
					username: JIRA_API_EMAIL,
					password: JIRA_API_TOKEN,
				},
			},
		);
		// Extract the status from the response
		return response.data.fields.status.name;
	} catch (error) {
		if (error.response?.status === 404) {
			console.warn(`Ticket ${ticketKey} not found in Jira.`);
			return null; // Ticket no longer exists
		}
		console.error(
			`Error fetching ticket status for ${ticketKey}:`,
			error.response?.data || error.message,
		);
		throw error; // Rethrow other errors
	}
};

const validateTrackedVulnerabilities = async (trackedVulnerabilities) => {
	const updatedTrackedVulnerabilities = { ...trackedVulnerabilities };

	for (const [id, { ticketKey, module_name }] of Object.entries(
		trackedVulnerabilities,
	)) {
		console.log(
			`Checking status of Jira ticket ${ticketKey} for ${module_name}...`,
		);
		const status = await getJiraTicketStatus(ticketKey);

		if (!status) {
			// Ticket no longer exists, remove it from tracking
			console.log(
				`Ticket ${ticketKey} no longer exists. Removing from tracking.`,
			);
			delete updatedTrackedVulnerabilities[id];
		} else if (
			status.toLowerCase() === "closed" ||
			status.toLowerCase() === "done"
		) {
			// Ticket is closed, remove it from tracking
			console.log(`Ticket ${ticketKey} is closed. Removing from tracking.`);
			delete updatedTrackedVulnerabilities[id];
		} else {
			// Ticket is still open, keep it in the tracking file
			console.log(`Ticket ${ticketKey} is still open (${status}).`);
		}
	}

	// Save the updated tracking file
	saveTrackedVulnerabilities(updatedTrackedVulnerabilities);
	return updatedTrackedVulnerabilities;
};

const validateTrackedWithJira = async (trackedVulnerabilities, epicKey) => {
	// Fetch the child issues from Jira
	console.log(`Fetching child issues for epic ${epicKey}...`);
	const childIssues = await fetchChildIssues(epicKey);

	// Create a map of child issues from Jira
	const jiraIssuesMap = {};
	childIssues.forEach((issue) => {
		jiraIssuesMap[issue.key] = issue;
	});

	// Update the tracking file
	const updatedTrackedVulnerabilities = {};

	// Check if all tracked vulnerabilities still exist in Jira
	for (const [id, { ticketKey, module_name }] of Object.entries(
		trackedVulnerabilities,
	)) {
		if (jiraIssuesMap[ticketKey]) {
			// Ticket exists in Jira, keep it in the tracking file
			updatedTrackedVulnerabilities[id] = {
				module_name,
				ticketKey,
			};
			console.log(
				`Ticket ${ticketKey} (${module_name}) is valid and still tracked.`,
			);
		} else {
			// Ticket no longer exists in Jira, remove it
			console.log(
				`Ticket ${ticketKey} (${module_name}) no longer exists in Jira. Removing from tracking.`,
			);
		}
	}

	// Check if any tickets from Jira are missing in the tracking file
	childIssues.forEach((issue) => {
		// If the ticket is not already in the tracking file, add it
		const isTracked = Object.values(trackedVulnerabilities).some(
			(tracked) => tracked.ticketKey === issue.key,
		);
		if (!isTracked) {
			// Add the missing ticket to the tracking file
			const id = `jira-${issue.key}`;
			updatedTrackedVulnerabilities[id] = {
				module_name: issue.summary || "Unknown",
				ticketKey: issue.key,
			};
			console.log(
				`Ticket ${issue.key} (${issue.summary}) is missing from tracking. Adding it.`,
			);
		}
	});

	// Save the updated tracking file
	saveTrackedVulnerabilities(updatedTrackedVulnerabilities);
	return updatedTrackedVulnerabilities;
};

// Helper function to read/write tracked vulnerabilities
const loadTrackedVulnerabilities = () => {
	if (fs.existsSync(TRACKING_FILE)) {
		return JSON.parse(fs.readFileSync(TRACKING_FILE, "utf-8"));
	}
	return {};
};

const saveTrackedVulnerabilities = (data) => {
	fs.writeFileSync(TRACKING_FILE, JSON.stringify(data, null, 2));
};

// Run `yarn audit` and parse vulnerabilities
const runYarnAudit = (yarnVersion) => {
	return new Promise((resolve, reject) => {
		const vulnerabilities = [];

		let yarnAudit = "";

		if (yarnVersion.startsWith("4.")) {
			yarnAudit = spawn("yarn", ["npm", "audit", "-R", "--json"]);
		} else {
			yarnAudit = spawn("yarn", ["audit", "--json"]);
		}

		yarnAudit.stdout.on("data", (data) => {
			const lines = data.toString().split("\n");
			lines.forEach((line) => {
				try {
					const jsonLine = JSON.parse(line);

					// Different parsing logic based on Yarn version
					if (yarnVersion.startsWith("1.")) {
						// Yarn v1.x parsing
						if (jsonLine.type === "auditAdvisory") {
							const advisory = jsonLine.data.advisory;
							const vulnerability = {
								module_name: advisory.module_name,
								id: advisory.id,
								issue: advisory.title,
								url: advisory.url,
								severity: advisory.severity,
								vulnerable_versions: advisory.vulnerable_versions,
								tree_versions: advisory.findings.map((f) => f.version),
								dependents: advisory.findings.map((f) => f.paths).flat(),
							};
							vulnerabilities.push(vulnerability);
						}
					} else if (
						yarnVersion.startsWith("2.") ||
						yarnVersion.startsWith("3.")
					) {
						// Yarn v2.x or v3.x parsing
						// Adjust parsing logic if needed (similar to v1 but with slight changes)
						if (jsonLine.type === "auditAdvisory" || jsonLine.advisory) {
							const advisory = jsonLine.advisory || jsonLine.data.advisory;
							const vulnerability = {
								module_name: advisory.module_name,
								id: advisory.id,
								issue: advisory.title,
								url: advisory.url,
								severity: advisory.severity,
								vulnerable_versions: advisory.vulnerable_versions,
								tree_versions: advisory.findings.map((f) => f.version),
								dependents: advisory.findings.map((f) => f.paths).flat(),
							};
							vulnerabilities.push(vulnerability);
						}
					} else if (yarnVersion.startsWith("4.")) {
						// Yarn v4.x parsing (current implementation)
						if (jsonLine.value && jsonLine.children) {
							const vulnerability = {
								module_name: jsonLine.value,
								id: jsonLine.children.ID,
								issue: jsonLine.children.Issue,
								url: jsonLine.children.URL,
								severity: jsonLine.children.Severity,
								vulnerable_versions: jsonLine.children["Vulnerable Versions"],
								tree_versions: jsonLine.children["Tree Versions"],
								dependents: jsonLine.children.Dependents,
							};
							vulnerabilities.push(vulnerability);
						}
					}
				} catch (err) {
					// Ignore lines that cannot be parsed as JSON
				}
			});
		});

		yarnAudit.stderr.on("data", (data) => {
			console.error("Error output from yarn audit:", data.toString());
		});

		yarnAudit.on("close", (code) => {
			resolve(vulnerabilities);
		});
	});
};

// Function to load and populate the Jira issue template
const loadIssueTemplate = (templatePath, data) => {
	try {
		// Read the markdown template
		const template = fs.readFileSync(templatePath, "utf-8");

		// Replace placeholders with actual values
		return template.replace(
			/{{(.*?)}}/g,
			(_, key) => data[key.trim()] || "N/A",
		);
	} catch (error) {
		console.error(`Failed to load issue template: ${error.message}`);
		process.exit(1); // Exit if the template cannot be loaded
	}
};

// Create a Jira ticket for a vulnerability
const createJiraTicket = async (vulnerability, JIRA_EPIC_KEY) => {
	const {
		module_name,
		id,
		issue,
		url,
		severity,
		vulnerable_versions,
		tree_versions,
		dependents,
	} = vulnerability;

	// Load and populate the issue template
	const templatePath = path.join(__dirname, "templates/jira-issue-template.md");
	const description = loadIssueTemplate(templatePath, {
		id,
		module_name,
		issue,
		url,
		severity,
		vulnerable_versions: vulnerable_versions || "N/A",
		tree_versions: (tree_versions || []).join(", "),
		dependents: (dependents || []).join(", "),
	});

	const issueData = {
		fields: {
			project: {
				key: JIRA_PROJECT_KEY,
			},
			summary: `[${severity.toUpperCase()}] Vulnerability in ${module_name}`,
			description,
			issuetype: {
				name: "Code Task", // Adjust the issue type to match your Jira setup
			},
			parent: {
				key: JIRA_EPIC_KEY,
			},
			priority: {
				name: jiraFriendlyCaseSeverity(severity), // Set the priority based on severity
			},
		},
	};

	try {
		const response = await axios.post(
			`${JIRA_BASE_URL}/rest/api/2/issue`,
			issueData,
			{
				auth: {
					username: JIRA_API_EMAIL,
					password: JIRA_API_TOKEN,
				},
			},
		);
		console.log(`Created Jira ticket: ${response.data.key}`);
		return response.data.key;
	} catch (error) {
		console.error(
			"Error creating Jira ticket:",
			error.response?.data || error.message,
		);
		return null;
	}
};

// Main function
const main = async () => {
	console.log("Running yarn audit...");
	// Detect the Yarn version
	const yarnVersion = getYarnVersion();

	let trackedVulnerabilities = loadTrackedVulnerabilities();

	// Validate the tracking file against Jira
	console.log("Validating tracked tickets with Jira...");
	trackedVulnerabilities = await validateTrackedWithJira(
		trackedVulnerabilities,
		JIRA_EPIC_KEY,
	);

	trackedVulnerabilities = await validateTrackedVulnerabilities(
		trackedVulnerabilities,
	);

	const vulnerabilities = await runYarnAudit(yarnVersion);

	for (const vulnerability of vulnerabilities) {
		const { id, module_name } = vulnerability;

		if (trackedVulnerabilities[id]) {
			console.log(`Vulnerability ${id} (${module_name}) already tracked.`);
			continue;
		}

		console.log(
			`Creating Jira ticket for vulnerability ${id} (${module_name})...`,
		);
		const ticketKey = await createJiraTicket(vulnerability, JIRA_EPIC_KEY);

		if (ticketKey) {
			trackedVulnerabilities[id] = {
				module_name,
				ticketKey,
			};
			saveTrackedVulnerabilities(trackedVulnerabilities);
		}
	}

	console.log("Script completed.");
};

// Run the script
main().catch((error) => {
	console.error("Error:", error);
});
