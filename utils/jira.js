const axios = require("axios");
require("dotenv").config(); // Load environment variables from .env

const JIRA_BASE_URL = process.env.JIRA_BASE_URL;
const JIRA_PROJECT_KEY = process.env.JIRA_PROJECT_KEY;
const JIRA_API_EMAIL = process.env.JIRA_API_EMAIL;
const JIRA_API_TOKEN = process.env.JIRA_API_TOKEN;
const JIRA_EPIC_KEY = process.env.JIRA_EPIC_KEY;

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

module.exports = {
	jiraFriendlyCaseSeverity,
	fetchChildIssues,
	getJiraTicketStatus,
};
