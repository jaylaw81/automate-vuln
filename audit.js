const { spawn } = require("child_process");
const axios = require("axios");
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
const runYarnAudit = () => {
	return new Promise((resolve, reject) => {
		const vulnerabilities = [];
		const yarnAudit = spawn("yarn", ["npm", "audit", "-R", "--json"]);

		yarnAudit.stdout.on("data", (data) => {
			const lines = data.toString().split("\n");
			lines.forEach((line) => {
				try {
					const jsonLine = JSON.parse(line);

					// Check if this is a vulnerability report line
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
				} catch (err) {
					// Ignore lines that cannot be parsed as JSON
				}
			});
		});

		yarnAudit.stderr.on("data", (data) => {
			console.error("Error output from yarn audit:", data.toString());
		});

		yarnAudit.on("close", (code) => {
			if (code === 1) {
				resolve(vulnerabilities);
			} else {
				reject(new Error(`yarn audit exited with code ${code}`));
			}
		});
	});
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

	const issueData = {
		fields: {
			project: {
				key: JIRA_PROJECT_KEY,
			},
			summary: `[${severity.toUpperCase()}] Vulnerability in ${module_name}`,
			description: `**Issue ID**: ${id}
  **Issue**: ${issue}
  **Severity**: ${severity}
  **URL**: [${url}](${url})
  **Vulnerable Versions**: ${vulnerable_versions || "N/A"}
  **Tree Versions**: ${tree_versions.join(", ") || "N/A"}
  **Dependents**: ${dependents.join(", ") || "N/A"}
  
  Please address this issue as soon as possible.`,
			issuetype: {
				name: "Code Task", // Adjust the issue type to match your Jira setup
			},
			parent: {
				key: JIRA_EPIC_KEY,
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
	const vulnerabilities = await runYarnAudit();

	const trackedVulnerabilities = loadTrackedVulnerabilities();

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
