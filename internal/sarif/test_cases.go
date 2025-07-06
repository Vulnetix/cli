package sarif

// ComprehensiveSARIFTestCases contains test cases covering various SARIF specification scenarios
var ComprehensiveSARIFTestCases = []struct {
	Name        string
	SARIF       string
	ShouldPass  bool
	Version     string
	Description string
}{
	{
		Name:        "Valid SARIF 2.1.0 - Minimal",
		ShouldPass:  true,
		Version:     "2.1.0",
		Description: "Minimal valid SARIF 2.1.0 document",
		SARIF: `{
			"version": "2.1.0",
			"runs": [
				{
					"tool": {
						"driver": {
							"name": "TestTool"
						}
					}
				}
			]
		}`,
	},
	{
		Name:        "Valid SARIF 2.1.0 - Comprehensive",
		ShouldPass:  true,
		Version:     "2.1.0",
		Description: "Comprehensive SARIF 2.1.0 with results, rules, and artifacts",
		SARIF: `{
			"version": "2.1.0",
			"runs": [
				{
					"tool": {
						"driver": {
							"name": "ESLint",
							"version": "8.0.0",
							"informationUri": "https://eslint.org",
							"semanticVersion": "8.0.0",
							"rules": [
								{
									"id": "no-unused-vars",
									"shortDescription": {
										"text": "Disallow unused variables"
									},
									"fullDescription": {
										"text": "Variables that are declared and not used anywhere in the code are most likely an error due to incomplete refactoring."
									},
									"helpUri": "https://eslint.org/docs/rules/no-unused-vars"
								}
							]
						}
					},
					"artifacts": [
						{
							"location": {
								"uri": "src/main.js"
							},
							"length": 1024,
							"sourceLanguage": "javascript"
						}
					],
					"results": [
						{
							"ruleId": "no-unused-vars",
							"ruleIndex": 0,
							"level": "warning",
							"message": {
								"text": "'unusedVar' is assigned a value but never used.",
								"markdown": "**unusedVar** is assigned a value but never used."
							},
							"locations": [
								{
									"physicalLocation": {
										"artifactLocation": {
											"uri": "src/main.js",
											"index": 0
										},
										"region": {
											"startLine": 42,
											"startColumn": 5,
											"endLine": 42,
											"endColumn": 14,
											"charOffset": 1000,
											"charLength": 9
										}
									}
								}
							],
							"fingerprints": {
								"0": "abc123def456"
							},
							"partialFingerprints": {
								"primaryLocationLineHash": "7d4f2c8a9b1e3f6d"
							}
						}
					],
					"invocation": {
						"executionSuccessful": true,
						"commandLine": "eslint src/main.js",
						"arguments": ["src/main.js"],
						"responseFiles": [
							{
								"uri": "output.sarif",
								"index": 0
							}
						],
						"startTimeUtc": "2023-12-01T10:00:00.000Z",
						"endTimeUtc": "2023-12-01T10:00:05.000Z"
					}
				}
			]
		}`,
	},
	{
		Name:        "Valid SARIF 2.0.0 - Basic",
		ShouldPass:  true,
		Version:     "2.0.0",
		Description: "Valid SARIF 2.0.0 document",
		SARIF: `{
			"version": "2.0.0",
			"runs": [
				{
					"tool": {
						"driver": {
							"name": "TestTool",
							"version": "1.0.0"
						}
					},
					"results": [
						{
							"message": {
								"text": "Test result message"
							},
							"ruleId": "test-rule",
							"level": "error"
						}
					]
				}
			]
		}`,
	},
	{
		Name:        "Valid SARIF 2.1.0 - Multiple Runs",
		ShouldPass:  true,
		Version:     "2.1.0",
		Description: "SARIF with multiple runs from different tools",
		SARIF: `{
			"version": "2.1.0",
			"runs": [
				{
					"tool": {
						"driver": {
							"name": "ESLint",
							"version": "8.0.0"
						}
					},
					"results": [
						{
							"message": {
								"text": "ESLint finding"
							},
							"ruleId": "no-unused-vars"
						}
					]
				},
				{
					"tool": {
						"driver": {
							"name": "Bandit",
							"version": "1.7.0"
						}
					},
					"results": [
						{
							"message": {
								"text": "Security vulnerability detected"
							},
							"ruleId": "B602",
							"level": "high"
						}
					]
				}
			]
		}`,
	},
	{
		Name:        "Valid SARIF 2.1.0 - With Notifications",
		ShouldPass:  true,
		Version:     "2.1.0",
		Description: "SARIF with notifications and invocation details",
		SARIF: `{
			"version": "2.1.0",
			"runs": [
				{
					"tool": {
						"driver": {
							"name": "CodeQL",
							"version": "2.11.0",
							"notifications": [
								{
									"id": "CTX001",
									"shortDescription": {
										"text": "Context message"
									},
									"fullDescription": {
										"text": "Additional context for analysis"
									}
								}
							]
						}
					},
					"invocation": {
						"executionSuccessful": true,
						"toolExecutionNotifications": [
							{
								"level": "note",
								"message": {
									"text": "Analysis completed successfully"
								},
								"descriptor": {
									"id": "CTX001"
								}
							}
						]
					},
					"results": []
				}
			]
		}`,
	},
	{
		Name:        "Invalid SARIF - Missing Version",
		ShouldPass:  false,
		Version:     "",
		Description: "SARIF missing required version field",
		SARIF: `{
			"runs": [
				{
					"tool": {
						"driver": {
							"name": "TestTool"
						}
					}
				}
			]
		}`,
	},
	{
		Name:        "Invalid SARIF - Unsupported Version",
		ShouldPass:  false,
		Version:     "3.0.0",
		Description: "SARIF with unsupported version",
		SARIF: `{
			"version": "3.0.0",
			"runs": [
				{
					"tool": {
						"driver": {
							"name": "TestTool"
						}
					}
				}
			]
		}`,
	},
	{
		Name:        "Invalid SARIF - Missing Runs",
		ShouldPass:  false,
		Version:     "2.1.0",
		Description: "SARIF missing required runs array",
		SARIF: `{
			"version": "2.1.0"
		}`,
	},
	{
		Name:        "Invalid SARIF - Empty Runs",
		ShouldPass:  false,
		Version:     "2.1.0",
		Description: "SARIF with empty runs array",
		SARIF: `{
			"version": "2.1.0",
			"runs": []
		}`,
	},
	{
		Name:        "Invalid SARIF - Missing Tool Driver Name",
		ShouldPass:  false,
		Version:     "2.1.0",
		Description: "SARIF missing required tool driver name",
		SARIF: `{
			"version": "2.1.0",
			"runs": [
				{
					"tool": {
						"driver": {
							"version": "1.0.0"
						}
					}
				}
			]
		}`,
	},
	{
		Name:        "Invalid SARIF - Missing Message Text",
		ShouldPass:  false,
		Version:     "2.1.0",
		Description: "SARIF result missing required message text",
		SARIF: `{
			"version": "2.1.0",
			"runs": [
				{
					"tool": {
						"driver": {
							"name": "TestTool"
						}
					},
					"results": [
						{
							"ruleId": "test-rule",
							"message": {}
						}
					]
				}
			]
		}`,
	},
	{
		Name:        "Invalid SARIF - Malformed JSON",
		ShouldPass:  false,
		Version:     "",
		Description: "SARIF with invalid JSON syntax",
		SARIF: `{
			"version": "2.1.0",
			"runs": [
				{
					"tool": {
						"driver": {
							"name": "TestTool"
					}
				}
			]
		}`,
	},
	{
		Name:        "Edge Case - Large SARIF",
		ShouldPass:  true,
		Version:     "2.1.0",
		Description: "Large SARIF with many results",
		SARIF: `{
			"version": "2.1.0",
			"runs": [
				{
					"tool": {
						"driver": {
							"name": "MassAnalyzer",
							"version": "1.0.0"
						}
					},
					"results": [
						{
							"message": {
								"text": "Finding 1"
							},
							"ruleId": "rule-1",
							"level": "info"
						},
						{
							"message": {
								"text": "Finding 2"
							},
							"ruleId": "rule-2",
							"level": "warning"
						}
					]
				}
			]
		}`,
	},
	{
		Name:        "Edge Case - Unicode Content",
		ShouldPass:  true,
		Version:     "2.1.0",
		Description: "SARIF with Unicode characters in content",
		SARIF: `{
			"version": "2.1.0",
			"runs": [
				{
					"tool": {
						"driver": {
							"name": "UnicodeAnalyzer",
							"version": "1.0.0"
						}
					},
					"results": [
						{
							"message": {
								"text": "Unicode test: 你好世界 🌍 Здравствуй мир"
							},
							"ruleId": "unicode-test",
							"locations": [
								{
									"physicalLocation": {
										"artifactLocation": {
											"uri": "src/файл.js"
										},
										"region": {
											"startLine": 1,
											"snippet": {
												"text": "// Comment with émojis: 🚀✨"
											}
										}
									}
								}
							]
						}
					]
				}
			]
		}`,
	},
	{
		Name:        "Edge Case - Empty Results Array",
		ShouldPass:  true,
		Version:     "2.1.0",
		Description: "Valid SARIF with empty results array",
		SARIF: `{
			"version": "2.1.0",
			"runs": [
				{
					"tool": {
						"driver": {
							"name": "CleanTool",
							"version": "1.0.0"
						}
					},
					"results": []
				}
			]
		}`,
	},
}