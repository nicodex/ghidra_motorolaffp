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

import java.awt.Font;
import java.awt.FontMetrics;
import java.util.List;

import javax.swing.JMenuItem;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;

import nicode.program.model.data.MotorolaFfpDataType;

public class ConvertToMotorolaFfpEquateAction extends ListingContextAction {
	private final ConvertToMotorolaFfpEquatePlugin plugin;
	private final MotorolaFfpDataType dataType;
	private FontMetrics metrics;

	public ConvertToMotorolaFfpEquateAction(ConvertToMotorolaFfpEquatePlugin plugin) {
		super("Convert To MotorolaFFP equate", plugin.getName());
		this.plugin = plugin;
		this.dataType = new MotorolaFfpDataType();

		setPopupMenuData(new MenuData(new String[] { "Convert", "" }, "Convert"));
		setEnabled(true);
	}

	String convertToString(Program program, Scalar scalar) {
		if (scalar != null) {
			// Allow smaller values to support signed type propagation
			long signedValue = scalar.getSignedValue();
			if (Integer.MIN_VALUE <= signedValue && signedValue <= Integer.MAX_VALUE) {
				int encodedValue = (int) signedValue;
				float floatValue = dataType.getHostFloat(encodedValue);
				Float value = Float.valueOf(floatValue);
				return value.toString();
			}
		}
		return null;
	}

	CodeUnit getCodeUnit(ListingActionContext context) {
		Address address = context.getAddress();
		if (address != null) {
			return context.getProgram().getListing().getCodeUnitContaining(address);
		}
		return null;
	}

	int getOperandIndex(ListingActionContext context) {
		ProgramLocation location = context.getLocation();
		if (location instanceof OperandFieldLocation) {
			return ((OperandFieldLocation) location).getOperandIndex();
		}
		return -1;
	}

	Scalar getScalar(ListingActionContext context) {
		CodeUnit cu = getCodeUnit(context);
		Scalar scalar = getScalar(cu, context);
		return scalar;
	}

	private int stringWidth(String s) {
		if (metrics == null) {
			JMenuItem item = new JMenuItem();
			Font font = item.getFont();
			metrics = plugin.getTool().getActiveWindow().getFontMetrics(font);
		}
		int w = metrics.stringWidth(s);
		if (w == 0) {
			return 10 * s.length();
		}
		return w;
	}

	private String getStandardLengthString(String baseString) {
		int baseWidth = stringWidth(baseString);
		int spaceWidth = stringWidth(" ");
		int paddingSize = (140 - baseWidth) / spaceWidth;
		if (paddingSize <= 0) {
			return baseString;
		}
		StringBuilder buf = new StringBuilder(baseString);
		for (int i = 0; i < paddingSize; i++) {
			buf.append(" ");
		}
		return buf.toString();
	}

	private String getMenuName(Program program, Scalar scalar) {
		String valueString = convertToString(program, scalar);
		if (valueString == null) {
			return null;
		}
		return getStandardLengthString("MotorolaFFP:") + valueString;
	}

	private static int getSubOperandIndex(ListingActionContext context) {
		ProgramLocation location = context.getLocation();
		if (location instanceof OperandFieldLocation) {
			return ((OperandFieldLocation) location).getSubOperandIndex();
		}
		return -1;
	}

	private Scalar getScalar(CodeUnit cu, ListingActionContext context) {
		int opIndex = getOperandIndex(context);
		int subOpIndex = getSubOperandIndex(context);
		Scalar scalar = getScalar(cu, opIndex, subOpIndex);
		return scalar;
	}

	private Scalar getScalar(CodeUnit cu, int opIndex, int subOpIndex) {
		if (cu == null) {
			return null;
		}

		if (cu instanceof Data) {
			return cu.getScalar(opIndex);
		}

		if (subOpIndex < 0) {
			return null;
		}

		Instruction instruction = ((Instruction) cu);
		List<?> list = instruction.getDefaultOperandRepresentationList(opIndex);
		if (list == null) {
			return null;
		}

		int numSubOps = list.size();
		Scalar currentScalar = null;

		// Check from opIndex to End for scalar.
		for (int repIndex = subOpIndex; repIndex < numSubOps; repIndex++) {
			Object object = list.get(repIndex);
			if (object instanceof Scalar) {
				currentScalar = (Scalar) object;
				break;
			}
		}
		if (currentScalar == null) {
			for (int repIndex = subOpIndex - 1; repIndex >= 0; repIndex--) {
				Object object = list.get(repIndex);
				if (object instanceof Scalar) {
					currentScalar = (Scalar) object;
					break;
				}
			}
		}
		if (currentScalar == null) {
			return null;
		}

		// Only return scalar if we can find matching scalar in OpObjects
		Object[] opObjects = instruction.getOpObjects(opIndex);
		for (Object object : opObjects) {
			if (object instanceof Scalar && currentScalar.equals(object)) {
				return currentScalar;
			}
		}
		return null;
	}
	
	@Override
	public boolean isEnabledForContext(ListingActionContext context) {
		ProgramLocation loc = context.getLocation();
		if (!(loc instanceof OperandFieldLocation)) {
			return false;
		}
		Scalar scalar = getScalar(context);
		if (scalar == null) {
			return false;
		}
		CodeUnit cu = getCodeUnit(context);
		if (cu instanceof Data) {
			return false;
		}
		String menuName = getMenuName(context.getProgram(), scalar);
		if (menuName == null) {
			return false;
		}

		getPopupMenuData().setMenuItemNamePlain(menuName);

		return true;
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		ConvertToMotorolaFfpEquateCommand cmd = new ConvertToMotorolaFfpEquateCommand(this, context);
		if (context.hasSelection()) {
			plugin.getTool().executeBackgroundCommand(cmd, context.getProgram());
		}
		else {
			plugin.getTool().execute(cmd, context.getProgram());
		}
	}

}
