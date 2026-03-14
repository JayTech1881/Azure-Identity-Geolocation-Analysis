# Azure-Identity-Geolocation-Analysis
Azure-Identity-Geolocation-Analysis


 Objective
Investigate Azure sign-in failures and Azure resource write operations using Kusto Query Language (KQL), then visualize the activity geographically using GeoIP enrichment.

This project demonstrates how security analysts can detect suspicious activity by identifying where login attempts and administrative actions originate from.

 Technologies Used
• Microsoft Azure  
• Azure Log Analytics  
• Microsoft Sentinel  
• Kusto Query Language (KQL)  
• GeoIP Watchlist  
• Map Visualization  

 Scenario

An organization wants to monitor where Azure activity is coming from in order to detect suspicious sign-ins or administrative actions from unusual locations.

Two datasets were analyzed:

1. Azure AD Sign-in failures
2. Azure Activity write operations

Both datasets were enriched with GeoIP information and visualized on a geographic map.

 Lab Activities

• Queried **SigninLogs** to identify failed login attempts  
• Extracted geolocation details such as latitude, longitude, city, and country  
• Counted login attempts per user and location  

• Queried **AzureActivity** logs to identify successful resource write operations  
• Filtered out service principal GUID identities to focus on human user activity  
• Extracted caller IP addresses  

• Used **GeoIP Watchlist** to map IP addresses to geographic locations  
• Enriched log data with country, city, latitude, and longitude  

• Built a **map visualization** to show where Azure activity originated

 Example Detection Questions

This analysis helps answer security questions such as:

• Are login attempts coming from unusual countries?  
• Are administrative Azure changes happening from unexpected locations?  
• Is a user attempting multiple logins from different geographic regions?  

 Security Insights

This investigation highlights how geographic analysis can help detect:

• Suspicious login activity  
• Potential credential compromise  
• Unauthorized administrative changes  
• Unusual access patterns  

 Lessons Learned

Security monitoring is more effective when log data is enriched with contextual information like geolocation.

By combining KQL queries with GeoIP data, analysts can quickly identify abnormal behavior and investigate potential threats.

## Example Queries

### Sign-in Failure Analysis

```kql
SigninLogs
| where ResultType != 0 and Identity !contains "-"
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| order by LoginCount desc
| project Identity, Latitude, Longitude, City, Country, LoginCount
