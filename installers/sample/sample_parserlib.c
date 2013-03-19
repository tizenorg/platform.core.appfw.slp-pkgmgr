/*
 * slp-pkgmgr
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>,
 * Jaeho Lee <jaeho81.lee@samsung.com>, Shobhit Srivastava <shobhit.s@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */





/* sample_parserlib.c
 * test package
 */

#include <stdio.h>
#include <string.h>
#include <libxml/xmlreader.h>

/* debug output */
#include <dlog.h>
#undef LOG_TAG
#define LOG_TAG "PKGMGR_PARSER"

#define DBGE(fmt, arg...) LOGE("[%s,%d] "fmt, __FUNCTION__, __LINE__, ##arg)
#define DBGI(fmt, arg...) LOGD("[%s,%d] "fmt, __FUNCTION__, __LINE__, ##arg)


static void
print_element_names(xmlNode * a_node)
{
    xmlNode *cur_node = NULL;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            DBGI("node type: Element, name: %s\n", cur_node->name);
        }

        print_element_names(cur_node->children);
    }
}


__attribute__ ((visibility("default")))
int PKGMGR_PARSER_PLUGIN_INSTALL(xmlDocPtr docPtr)
{
	xmlNode *root_element = NULL;

	xmlTextReaderPtr reader = xmlReaderWalker(docPtr);
	if(reader != NULL) {
		int ret = xmlTextReaderRead(reader);
		while(ret == 1) {
			const xmlChar   *name;
			name = xmlTextReaderConstName(reader);
			DBGI("name %s", name?(const char *)name:"NULL");
			ret = xmlTextReaderRead(reader);
		}
		xmlFreeTextReader(reader);

		if(ret != 0) {
			DBGE("failed to parse");
		}
	}

	/*Get the root element node */
	root_element = xmlFirstElementChild(xmlDocGetRootElement(docPtr));

	print_element_names(root_element);

	return 0;
}

