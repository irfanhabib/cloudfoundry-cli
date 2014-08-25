## v6.5.0
* Implement Space Quota commands (create, update, delete, list, assignment)
* Change cf space command to show information on the quota associated with the space. [#77389658]
* Tweak help text for "push" [#76417956]
* Remove default async timeout. [#76995182]
* Change update-service-broker to take in optional flags. [#63480754]
* Update plan visibility search to take advantage of API queries [#76753494]
* Add instance memory to quota, quotas, and update-quota. [#76292608]

## v6.4.0
* Implement service-access command.
* Implement enable-service-access command.
* Implement disable-service-access command.
* Merge pull request #237 from sykesm/hm-unknown-instances Use '?' instead of '-1' when running instances is unknown [#76461268]
* Merge pull request #239 from johannespetzold/loggregator-debug-printer CF_TRACE option for cf logs
* Stop using deprecated endpoints for domains. [#76723550]
* Refresh auth token on all service-access commands. [#76831670]
* Stop CLI from hanging when Loggregator keeps returning errors. [#76545800]
* Merge pull request #234 from fraenkel/cfignoreIgnored Copy cfignore to upload directory to properly ignore files
* Pass in ProxyFromEnvironment function to loggregator_consumer. [#75343416]
* Merge pull request #227 from XenoPhex/master By Grabthar hammer, by the sons of Worvan, you shall be avenged. Also, sorting.
* Add cli version to the "aww shucks" messsage. [#75131050]
* Merge pull request #223 from fraenkel:connectTimeout Use a connect timeout whenever making connections
* Merge pull request #225 from cloudfoundry/flush-log-messages Fix inter-woven output during start
* Merge pull request #222 from fraenkel/closeBody Close the response body
* Merge pull request #221 from jpalermo/master Fix base64 padding

## v6.3.2
* Provides "pretty printed" output of config JSON. [#74664516]
* Undo recursive copy of files [#75530934]
* Merge all translations into monolithic files. [#74408246]
* Remove some words from dictionary [#75469600]
* Merge pull request #210 from wdneto/pt_br Initial pt-br translation [#75083626]

## v6.3.1
* Remove Korean as a supported language. - goi18n does not currently support it, so it is in the same boat as Russian.
* Forcing default domain to be the first shared domain. Closes #209 [#75067850]
* The ru_RU locale is not supported. The go-i18n tool that we use does not support this locale at the moment and thus we should not be offering translation until such time as that changes. Closes #208 [#75021420]
* Adding in tool to fix json formatting
* Fixes spacing and file permissions for all JSON files. Spacing i/s now a standard 3 spaces. Permissions are now 0644.
* Merges Spanish Translations. Thanks, @bonzofenix! Merge pr/207 [#74857552]
* Merge Chinese Translations from a lot of effort by @wayneeseguin. Thanks also to @tsjsdbd, @isuperbb, @shenyefeng, @hujie5592427, @haojun, @wsxiaozhang and @Kaixiang! Closes #205 [#74772500]
* Travis-CI builds should run i18n tests Also, fail if any of those other commands fail

## v6.3.0
* Add commands for managing security groups
* Push no longer uses deprecated endpoint for domains. [#74737286]
* `cf` always returns exit code 1 on error [#74565136]
* Json is interpreted properly for create/update user-provided-service. Fixes issue #193 [#73971288]
* Made '--help' flag match the help text from the 'help' command [Finishes #73655496]

## v6.2.0
* Internationalize the CLI [#70551274](https://www.pivotaltracker.com/story/show/70551274), [#71441196](https://www.pivotaltracker.com/story/show/71441196), [#72633034](https://www.pivotaltracker.com/story/show/72633034), [#72633034](https://www.pivotaltracker.com/story/show/72633034), [#72633036](https://www.pivotaltracker.com/story/show/72633036), [#72633038](https://www.pivotaltracker.com/story/show/72633038), [#72633042](https://www.pivotaltracker.com/story/show/72633042), [#72633044](https://www.pivotaltracker.com/story/show/72633044), [#72633056](https://www.pivotaltracker.com/story/show/72633056), [#72633062](https://www.pivotaltracker.com/story/show/72633062), [#72633064](https://www.pivotaltracker.com/story/show/72633064), [#72633066](https://www.pivotaltracker.com/story/show/72633066), [#72633068](https://www.pivotaltracker.com/story/show/72633068), [#72633070](https://www.pivotaltracker.com/story/show/72633070), [#72633074](https://www.pivotaltracker.com/story/show/72633074), [#72633080](https://www.pivotaltracker.com/story/show/72633080), [#72633084](https://www.pivotaltracker.com/story/show/72633084), [#72633086](https://www.pivotaltracker.com/story/show/72633086), [#72633088](https://www.pivotaltracker.com/story/show/72633088), [#72633090](https://www.pivotaltracker.com/story/show/72633090), [#72633090](https://www.pivotaltracker.com/story/show/72633090), [#72633096](https://www.pivotaltracker.com/story/show/72633096), [#72633100](https://www.pivotaltracker.com/story/show/72633100), [#72633102](https://www.pivotaltracker.com/story/show/72633102), [#72633112](https://www.pivotaltracker.com/story/show/72633112), [#72633116](https://www.pivotaltracker.com/story/show/72633116), [#72633118](https://www.pivotaltracker.com/story/show/72633118), [#72633126](https://www.pivotaltracker.com/story/show/72633126), [#72633128](https://www.pivotaltracker.com/story/show/72633128), [#72633130](https://www.pivotaltracker.com/story/show/72633130), [#70551274](https://www.pivotaltracker.com/story/show/70551274), [#71347218](https://www.pivotaltracker.com/story/show/71347218), [#71441196](https://www.pivotaltracker.com/story/show/71441196), [#71594662](https://www.pivotaltracker.com/story/show/71594662), [#71801388](https://www.pivotaltracker.com/story/show/71801388), [#72250906](https://www.pivotaltracker.com/story/show/72250906), [#72543282](https://www.pivotaltracker.com/story/show/72543282), [#72543404](https://www.pivotaltracker.com/story/show/72543404), [#72543994](https://www.pivotaltracker.com/story/show/72543994), [#72548944](https://www.pivotaltracker.com/story/show/72548944), [#72633064](https://www.pivotaltracker.com/story/show/72633064), [#72633108](https://www.pivotaltracker.com/story/show/72633108), [#72663452](https://www.pivotaltracker.com/story/show/72663452), [#73216920](https://www.pivotaltracker.com/story/show/73216920), [#73351056](https://www.pivotaltracker.com/story/show/73351056), [#73351056](https://www.pivotaltracker.com/story/show/73351056)]
* 'purge-service-offering' should fail if the request fails [[#73009140](https://www.pivotaltracker.com/story/show/73009140)]
* Pretty print JSON for `cf curl` [[#71425006](https://www.pivotaltracker.com/story/show/71425006)]
* CURL output can be directed to file via parameter `--output`.  [[#72659362](https://www.pivotaltracker.com/story/show/72659362)]
* Fix a source of flakiness in start [[#71778246](https://www.pivotaltracker.com/story/show/71778246)]
* Add build date time to the `--version` message, `cf --version` now reports [ISO 8601](http://en.wikipedia.org/wiki/ISO_8601) date [[#71446932](https://www.pivotaltracker.com/story/show/71446932)]
* Show system environment variables with `cf env` [[#71250896](https://www.pivotaltracker.com/story/show/71250896)]
* Fix double confirm prompt bug [[#70960378](https://www.pivotaltracker.com/story/show/70960378)]
* Fix create-buildpack from local directory [[#70766292](https://www.pivotaltracker.com/story/show/70766292)]
* Gateway respects user-defined Async timeout [[#71039042](https://www.pivotaltracker.com/story/show/71039042)]
* Bump async timeout to 10 minutes [[#70242130](https://www.pivotaltracker.com/story/show/70242130)]
* Trace should also respect the user config setting [[#71045364](https://www.pivotaltracker.com/story/show/71045364)]
* Add a 'cf config' command [[#70242276](https://www.pivotaltracker.com/story/show/70242276)]
  - Uses --color value to enable/disable/ignore coloring [[#71045474](https://www.pivotaltracker.com/story/show/71045474), [#68903282](https://www.pivotaltracker.com/story/show/68903282)]
  - Add config --trace flag [[#68903318](https://www.pivotaltracker.com/story/show/68903318)]

## v6.1.2
* Added BUILDING.md document to describe our CI / build process
* Fixed regression where the last few log messages received would never be shown
  - affected commands include `cf start`, `cf logs` and `cf push`
* Fixed a bug in `cf push` related to windows and empty directories [#70470232] [#157](https://github.com/cloudfoundry/cli/issues/157)
* Fixed a bug in `cf space-users` and `cf org-users` that would incorrectly show all users
* `cf org $ORG_NAME` now displays the quota assigned to the org
* Fixed a bug where no log messages would be received if your access token had expired [#66242222]

## v6.1.1
- New quota CRUD commands for admins
- Only ignore `manifest.yml` at the app root directory [#70044992]
- Updating loggregator library experimental support for proxies [#70022322]
- Provide a `--sso` flag to `cf login` for SAML [#69963402, #69963432]
- Do not use deprecated domain endpoints in `cf push` [#69827262]
- Display `X-Cf-Warnings` at the end of all commands [#69300730]
* Add an `actor` column to the `cf events` table [#68771710]

## v6.1.0
* Refresh auth token at the beginning of `cf push` [#69034628]
* `cf routes` should have an org and space requirement [#68917070]
* Fix a bug with binding services in manifests [#68768046]
* Make delete confirmation messages more consistent [#62852994]
* Don`t upload manifest.yml by default [#68952284]
* Ignore mercurial metadata from app upload [#68952326]
* Make delete commands output more consistent [#62283088]
* Make `cf create-user` idempotent [#67241604]
* Allow `cf unset-env` to remove the last env var an app has [#68879028]
* Add a datetime for when the binary was built [#68515588]
* Omit application files when CC reports all files are staged [#68290696]
* Show actual error message from server on async job failure [#65222140]
* Use new domains endpoints based on API version [#64525814]
* Use different events APIs based on API version [#64525814]
* Updated help text and messaging
* Events commands only shows last 50 events in reverse chronological order [#67248400, #63488318, #66900178]
* Add -r flag to `cf delete` for deleting all the routes mapped to the app [#65781990]
* Scope route listed to the current space [#59926924]
* Include empty directories when pushing apps [#63163454]
* Fetch UAA endpoint in auth command [#68035332]
* Improve error message when memory/disk is given w/o unit [#64359068]
* Only allow positive instances, memory or disk for `cf push` and `cf scale` [#66799710]
* Allow passing "null" as a buildpack url for "cf push" [#67054262]
* Add disk quota flag to push cmd [#65444560]
* Add a script for updating links to stable release [#67993678]
* Suggest using random-route when route is already taken [#66791058]
* Prompt user for all password-type credentials in login [#67864534]
* Add random-route property to manifests (push treats this the same as the --random-hostname flag) [#62086514]
* Add --random-route flag to `cf push` [#62086514]
* Fix create-user when UAA is being directly used as auth server (if the authorization server doesn`t return an UAA endpoint link, assume that the auth server is the UAA, and use it for user management) [#67477014]
* `cf create-user` hides private data in `CF_TRACE` [#67055200]
* Persist SSLDisabled flag on config [#66528632]
* Respect --skip-ssl-validation flag [#66528632]
* Hide passwords in `CF_TRACE` [#67055218]
* Improve `cf api` and `cf login` error message around SSL validation errors [#67048868]
* In `cf api`, fail if protocol not specified and ssl cert invalid [#67048868]
* Clear session at beginning of `cf auth` [#66638776]
* When renaming targetted org, update org name in config file [#63087464]
* Make `cf target` clear org and space when necessary [#66713898]
* Add a -f flag to scale to force [#64067896]
* Add a confirmation prompt to `cf scale` [#64067896]
* Verify SSL certs when fetching buildpacks [#66365558]
* OS X installer errors out when attempting to install on pre 10.7 [#66547206]
* Add ability to scale app`s disk limit [#65444078]
* Switch out Gamble for candied yaml [#66181944]

## v6.0.2
* Fixed `cf push -p path/to/app.zip` on windows with zip files (eg: .zip, .war, .jar)

## v6.0.1
* Added purge-service-offering and migrate-service-instances commands
* Added -a flag to `cf org-users` that makes the command display all users, rather than only privileged users (#46)
* Fixed a bug when manifest.yml was zero bytes
* Improved error messages for commands that reference users (#79)
* Fixed crash when a manifest didn`t contain environment variables but there were environment variables set for the app previously
* Improved error messages for commands that require an API endpoint to be set
* Added timeout to all asynchronous requests
* Fixed `bad file descriptor` crash when API token expired before file upload
* Added timestamps and version information to request logs when `CF_TRACE` is enabled
* Added fallback to default log server endpoint for compatibility with older CF deployments
* Improved error messages for services and target commands
* Added support for URLs as arguments to create-buildpack command
* Added a homebrew recipe for cf -- usage: brew install cloudfoundry-cli
