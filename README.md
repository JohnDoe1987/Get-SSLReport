#Get-SSLReport.ps1

Get-SSLReport.ps1 is a PowerShell function which use the SSL Labs API to check servers SSL/TLS security.
You can use this script to bulk a list of servers or use it to automate your security monitoring.

This project is still in beta status. Feel free to report any bugs or feature requests.


##Parameters

Parameter: Hostname
Type: String
Required: Yes

Parameter: Publish
Type: boolean
Required: Yes

Parameter: startNew
Type: boolean
Required: No

Parameter: fromCache
Type: boolean
Required: No

Parameter: maxAge
Type: int
Required: No

Parameter: ignoreMismatch
Type: boolean
Required: No

Parameter: showChain
Type: boolean
Required: No


##Examples

Use this function in your PowerShell script or import it like this:

. .\Get-SSLReport.ps1

Generate a report and show results on [Qualys SSL Labs](https://www.ssllabs.com/) startpage.
Proceed the check also when the server certificate doesn't match the assessment hostname.

Get-SSLReport -Hostname www.letsencrypt.com -Publish $true -startNew $true -ignoreMismatch $true


Generate a report but don't show them on [Qualys SSL Labs](https://www.ssllabs.com/) startpage.
If there was a check since 24 hours, show the result from cache. If the cached check is older than 24 hours,
run a new check.
Proceed the check also when the server certificate doesn't match the assessment hostname.
Show also the certificate chain in the result.

Get-SSLReport -Hostname www.letsencrypt.com -Publish $false -startNew $false -fromCache $true -maxAge 24 -ignoreMismatch $true -showChain $true


##Coming soon

* Save output to file
* Send e-mail report
* Customize colors with .xml file


##Credits

- [Qualys SSL Labs](https://www.ssllabs.com/)


##License

Feel free to use or modify this script. Please credit to me.
