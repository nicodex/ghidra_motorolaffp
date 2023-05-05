/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nicode.app.plugin.core.equate;

import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Convert to MotorolaFFP equate",
	description = "This provide an action for converting scalar operands to MotorolaFFP equates.",
	servicesRequired = { CodeViewerService.class }
)
//@formatter:on
public class ConvertToMotorolaFfpEquatePlugin extends Plugin {

	public ConvertToMotorolaFfpEquatePlugin(PluginTool tool) {
		super(tool);

		tool.setMenuGroup(new String[] { "Convert" }, "equate"); // EquatePlugin.GROUP_NAME
		tool.addAction(new ConvertToMotorolaFfpEquateAction(this));
	}

}
