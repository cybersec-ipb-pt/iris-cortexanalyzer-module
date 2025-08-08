#!/usr/bin/env python3

import traceback
import time
from cortex4py.api import Api
from jinja2 import Template
import iris_interface.IrisInterfaceStatus as InterfaceStatus
from app.datamgmt.manage.manage_attribute_db import add_tab_attribute_field

class CortexanalyzerHandler(object):
    def __init__(self, mod_config, server_config, logger):
        self.mod_config = mod_config
        self.server_config = server_config
        self.log = logger

    def gen_report_from_template(self, html_template, cortexanalyzer_report, analyzer_name, id) -> InterfaceStatus:
        """
        Generates an HTML report for Domain, displayed as an attribute in the IOC
        :param html_template: A string representing the HTML template
        :param cortexanalyzer_report: The JSON report fetched with cortexanalyze API
        :param analyzer_name: Analyzer name
        :return: InterfaceStatus
        """

        template = Template(html_template.replace("Cortex Analyzer results", f"{analyzer_name} Report - Job ID: {id}").replace("drop_r_cortexanalyzer", f"drop_r_cortexanalyzer_{analyzer_name}").replace("rop_raw_cortexanalyzer", f"rop_raw_cortexanalyzer_{analyzer_name}").replace("cortexanalyzer_raw_ace", f"cortexanalyzer_raw_ace_{analyzer_name}"))
        pre_render = dict({"results": []})
        pre_render["results"] = cortexanalyzer_report

        try:
            rendered = template.render(pre_render)
        except Exception:
            print(traceback.format_exc())
            self.log.error(traceback.format_exc())

            return InterfaceStatus.I2Error(traceback.format_exc())

        return InterfaceStatus.I2Success(data=rendered)

    def handle_ioc(self, ioc, dataType):
        """
        Handles an IOC and adds Cortex Analyzer insights
        :param ioc: IOC instance
        :param dataType: IOC type
        :return: IIStatus
        """

        self.log.info(f"Getting {dataType} report for {ioc.ioc_value}")
        url = self.mod_config.get("cortexanalyze_url")
        apikey = self.mod_config.get("cortexanalyze_key")
        analyzers = self.mod_config.get("cortexanalyze_analyzer")

        api = Api(url, apikey, verify_cert=False)

        """
        Call Cortex via Cortex4py To check if Analyzer is Enabled
        :param ioc: IOC instance
        :return: IIStatus
        """

        available_analyzers = api.analyzers.find_all({}, range='all')
        all_analyzers, execution = ({} for _ in range(2))
        tags, rendered_report = ([] for _ in range(2))

        for available in available_analyzers:
            all_analyzers[available.name] = available.dataTypeList

        if isinstance(analyzers, str):
            analyzers = [a.strip() for a in analyzers.split(",")]

        """
        Call Cortex via Cortex4py To run Analyzer and Return Results
        :param ioc: IOC instance
        :return: IIStatus
        """

        for analyzer in analyzers:
            if analyzer not in all_analyzers.keys():
                self.log.error(f'{analyzer} was not found to be enabled. Enable the Analyzer in Cortex to continue')

                return InterfaceStatus.I2Error()
            else:
                self.log.info(f'{analyzer} was found to be enabled. Continuing')

            if dataType not in all_analyzers[analyzer]:
                continue

            job1 = api.analyzers.run_by_name(
                analyzer,
                {
                    "data": ioc.ioc_value,
                    "dataType": dataType,
                    "tlp": 1,
                    "message": "custom message sent to analyzer",
                },
                force=1,
            )

            r_json = job1.json()
            self.log.info(f'{analyzer} Job ID is: {r_json["id"]}')
            execution[analyzer] = [r_json, r_json["id"], r_json["status"], 0]

        for analyzer, (r_json, job_id, job_state, timer) in execution.items():
            while job_state != "Success":
                if timer == 60:
                    self.log.error(f"{analyzer} job failed to complete after 5 minutes.")
                    report = f"{analyzer} job failed to complete after 5 minutes."
                    break

                timer = timer + 1
                self.log.info(f'{analyzer} timer is: {timer}')

                if job_state == "Failure":
                    error_message = r_json["errorMessage"]
                    self.log.error(f'{analyzer} Failure: {error_message}')

                    if len(execution.keys()) == 1:
                        return InterfaceStatus.I2Error()

                    break
                else:
                    time.sleep(5)

                followup_request = api.jobs.get_by_id(job_id)
                r_json = followup_request.json()
                job_state = r_json["status"]

            if job_state == "Success":
                self.log.info(f"{analyzer} job completed successfully")
                report = api.jobs.get_report(job_id).report
                final_report = report["full"]

                try:
                    for summary in report["summary"]["taxonomies"]:
                        tags.append(f'{summary["namespace"]}:{summary["predicate"]}="{summary["value"].replace(",", ";")}"')

                    if analyzer == "VirusTotal_GetReport_3_1":
                        if int(report["full"]["attributes"]["last_analysis_stats"]["malicious"]) > 0:
                            tags.append('VT:Result="Malicious"')
                        elif int(report["full"]["attributes"]["last_analysis_stats"]["suspicious"]) > 0:
                            tags.append('VT:Result="Suspicious"')
                        else:
                            tags.append('VT:Result="Safe"')
                except:
                    pass

                if self.mod_config.get("cortexanalyzer_report_as_attribute") is True:
                    status = self.gen_report_from_template(html_template=self.mod_config.get("cortexanalyzer_domain_report_template"), cortexanalyzer_report=final_report, analyzer_name=analyzer, id=job_id)

                    if not status.is_success():
                        return status

                    rendered_report.append(status.get_data())

        if self.mod_config.get("cortexanalyzer_report_as_attribute") is True and len(rendered_report) != 0:
            if tags: rendered_report.append(str("<p>Results from analysis done on " + time.strftime("%Y-%m-%d", time.localtime()) + ": " + ", ".join(tags) + "</p>"))

            self.log.info(f"Adding new attribute CORTEX {dataType} Report to IOC")

            try:
                add_tab_attribute_field(
                    ioc,
                    tab_name="CORTEX Reports",
                    field_name="HTML report",
                    field_type="html",
                    field_value="".join(rendered_report),
                )
            except Exception:
                self.log.error(traceback.format_exc())

                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info("Skipped adding attribute report. Option disabled")

        ioc.ioc_tags = ",".join(list(dict.fromkeys([tag.strip() for tag in str(ioc.ioc_tags).split(",") if tag.strip()] + tags)))
        return InterfaceStatus.I2Success()