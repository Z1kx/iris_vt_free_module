#!/usr/bin/env python3
#
#  IRIS VT Module Source Code
#  contact@dfir-iris.org
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
import logging
import traceback

import virustotal_python
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.Session.verify = False

from iris_interface.IrisModuleInterface import IrisPipelineTypes, IrisModuleInterface, IrisModuleTypes
import iris_interface.IrisInterfaceStatus as InterfaceStatus
from app.datamgmt.manage.manage_attribute_db import add_tab_attribute_field

from iris_vt_free_module.vt_handler.vt_helper import gen_domain_report_from_template, gen_ip_report_from_template, \
    get_detected_urls_ratio, gen_hash_report_from_template


class VtHandler(object):
    def __init__(self, mod_config, server_config, logger):
        self.mod_config = mod_config
        self.server_config = server_config
        self.vt = self.get_vt_instance()
        self.log = logger

    def get_vt_instance(self):
        """
        Returns a VT API v3 instance (virustotal_python.Virustotal)
        """
        api_key = self.mod_config.get('vt_api_key')
        proxies = None
        if self.server_config.get('http_proxy') or self.server_config.get('https_proxy'):
            proxies = {}
            if self.server_config.get('http_proxy'):
                proxies['http'] = self.server_config.get('http_proxy')
            if self.server_config.get('https_proxy'):
                proxies['https'] = self.server_config.get('https_proxy')
        return virustotal_python.Virustotal(API_KEY=api_key, PROXIES=proxies)

    def _validate_report(self, report):
        self.log.info(f'VT report fetched.')
        results = report.get('results')
        if not results:
            self.log.error(f'Unable to get report. Is the API key valid ?')
            return InterfaceStatus.I2Error

        if results.get('response_code') == 0:
            self.log.error(f'Got invalid feedback from VT :: {results.get("verbose_msg")}')
            return InterfaceStatus.I2Error()

        return InterfaceStatus.I2Success(data=report)

    def tag_if_malicious_or_suspicious(self, context, ioc):
        """
        Tag an IOC if the detections ratio are higher than the configured threshold
        :param ioc: IOC checked
        :param context: VT report
        :return:
        """
        _, avg_detected_ratio, _ = get_detected_urls_ratio(context)

        if not avg_detected_ratio:

            pos = context.get('positives')
            total = context.get('total')
            if pos and total:
                avg_detected_ratio = round(float(pos)/float(total), 2) * 100

        if avg_detected_ratio:
            if ioc.ioc_tags is None:
                ioc.ioc_tags = ""

            if float(self.mod_config.get('vt_tag_malicious_threshold')) <= float(avg_detected_ratio):
                if f'vt:malicious' not in ioc.ioc_tags.split(','):
                    ioc.ioc_tags = f"{ioc.ioc_tags},vt:malicious"

            elif float(self.mod_config.get('vt_tag_suspicious_threshold')) <= float(avg_detected_ratio):
                if f'vt:suspicious' not in ioc.ioc_tags.split(','):
                    ioc.ioc_tags = f"{ioc.ioc_tags},vt:suspicious"

            else:
                if f'vt:suspicious' in ioc.ioc_tags.split(','):
                    ioc.ioc_tags = ioc.ioc_tags.replace('vt:suspicious', '').replace(',,', ',')
                if f'vt:malicious' in ioc.ioc_tags.split(','):
                    ioc.ioc_tags = ioc.ioc_tags.replace('vt:malicious', '').replace(',,', ',')

    def handle_vt_domain(self, ioc):
        """
        Handles an IOC of type domain and adds VT insights
        """
        self.log.info(f'Getting domain report for {ioc.ioc_value}')
        try:
            resp = self.vt.request(f"domains/{ioc.ioc_value}")
            results = resp.data
            if 'attributes' in results:
                results = results['attributes']
        except Exception as e:
            self.log.error(f'Error fetching domain report: {e}')
            return InterfaceStatus.I2Error(str(e))
        self.tag_if_malicious_or_suspicious(context=results, ioc=ioc)

        if self.mod_config.get('vt_domain_add_whois_as_desc') is True:
            if "WHOIS" not in ioc.ioc_description:
                self.log.info('Adding WHOIS information to IOC description')
                ioc.ioc_description = f"{ioc.ioc_description}\n\nWHOIS\n {results.get('whois')}"

            else:
                self.log.info('Skipped adding WHOIS. Information already present')
        else:
            self.log.info('Skipped adding WHOIS. Option disabled')

        if self.mod_config.get('vt_domain_add_subdomain_as_desc') is True:

            if "Subdomains" not in ioc.ioc_description:
                if results.get('subdomains'):
                    subd_data = [f"- {subd}\n" for subd in results.get('subdomains')]
                    self.log.info('Adding subdomains information to IOC description')
                    ioc.ioc_description = f"{ioc.ioc_description}\n\nSubdomains\n{subd_data}"
                else:
                    self.log.info('No subdomains in VT report')
            else:
                self.log.info('Skipped adding subdomains information. Information already present')
        else:
            self.log.info('Skipped adding subdomain information. Option disabled')

        if self.mod_config.get('vt_report_as_attribute') is True:
            self.log.info('Adding new attribute VT Domain Report to IOC')

            status = gen_domain_report_from_template(html_template=self.mod_config.get('vt_domain_report_template'),
                                                     vt_report=results)

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                add_tab_attribute_field(ioc, tab_name='VT Report', field_name="HTML report", field_type="html",
                                        field_value=rendered_report)

            except Exception:

                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info('Skipped adding attribute report. Option disabled')

        return InterfaceStatus.I2Success()

    def handle_vt_ip(self, ioc):
        """
        Handles an IOC of type IP and adds VT insights

        :param ioc: IOC instance
        :return: IIStatus
        """
        vt = self.get_vt_instance()

        self.log.info(f'Getting IP report for {ioc.ioc_value}')
        try:
            resp = self.vt.request(f"ip_addresses/{ioc.ioc_value}")
            results = resp.data
            if 'attributes' in results:
                results = results['attributes']
        except Exception as e:
            self.log.error(f'Error fetching IP report: {e}')
            return InterfaceStatus.I2Error(str(e))
        self.tag_if_malicious_or_suspicious(context=results, ioc=ioc)

        if self.mod_config.get('vt_ip_assign_asn_as_tag') is True:
            self.log.info('Assigning new ASN tag to IOC.')

            asn = results.get('asn')
            if asn is None:
                self.log.info('ASN was nul - skipping')

            if ioc.ioc_tags is None:
                ioc.ioc_tags = ""

            if f'ASN:{asn}' not in ioc.ioc_tags.split(','):
                ioc.ioc_tags = f"{ioc.ioc_tags},ASN:{asn}"
            else:
                self.log.info('ASN already tagged for this IOC. Skipping')

        if self.mod_config.get('vt_report_as_attribute') is True:
            self.log.info('Adding new attribute VT IP Report to IOC')

            status = gen_ip_report_from_template(html_template=self.mod_config.get('vt_ip_report_template'),
                                                 vt_report=results)

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                add_tab_attribute_field(ioc, tab_name='VT Report', field_name="HTML report", field_type="html",
                                        field_value=rendered_report)

            except Exception:
                print(traceback.format_exc())
                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info('Skipped adding attribute report. Option disabled')

        return InterfaceStatus.I2Success("Successfully processed IP")

    def handle_vt_hash(self, ioc):
        """
        Handles an IOC of type hash and adds VT insights
        """
        vt = self.get_vt_instance()
        self.log.info(f'Getting hash report for {ioc.ioc_value}')
        try:
            resp = self.vt.request(f"files/{ioc.ioc_value}")
            results = resp.data
            if 'attributes' in results:
                results = results['attributes']
        except Exception as e:
            self.log.error(f'Error fetching hash report: {e}')
            return InterfaceStatus.I2Error(str(e))
        self.tag_if_malicious_or_suspicious(context=results, ioc=ioc)

        if self.mod_config.get('vt_report_as_attribute') is True:
            self.log.info('Generating report from template')
            status = gen_hash_report_from_template(html_template=self.mod_config.get('vt_hash_report_template'),
                                                   vt_report=results)

            if not status.is_success():
                return status

            rendered_report = status.get_data()

            try:
                self.log.info('Adding new attribute VT hash Report to IOC')
                add_tab_attribute_field(ioc, tab_name='VT Report', field_name="HTML report", field_type="html",
                                        field_value=rendered_report)
                self.log.info('Done')

            except Exception:
                print(traceback.format_exc())
                self.log.error(traceback.format_exc())
                return InterfaceStatus.I2Error(traceback.format_exc())
        else:
            self.log.info('Skipped adding attribute report. Option disabled')

        return InterfaceStatus.I2Success("Successfully processed hash")