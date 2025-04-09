const fs = require("fs");
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

module.exports = {
	loadTrackedVulnerabilities,
	saveTrackedVulnerabilities,
	loadIssueTemplate,
};
