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

import java.util.List;
import java.util.Optional;

import ghidra.app.cmd.equate.ClearEquateCmd;
import ghidra.app.cmd.equate.SetEquateCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.util.ProgramSelection;
import ghidra.util.task.TaskMonitor;

public class ConvertToMotorolaFfpEquateCommand extends BackgroundCommand {
	private final ConvertToMotorolaFfpEquateAction action;
	private final ListingActionContext context;
	private final Program program;
	private String msg;

	public ConvertToMotorolaFfpEquateCommand(ConvertToMotorolaFfpEquateAction action,
			ListingActionContext context) {
		this.action = action;
		this.context = context;
		this.program = context.getProgram();
	}

	private boolean valuesAreDifferent(Equate equate, Scalar scalar) {
		long value = equate.getValue();
		return value != scalar.getSignedValue() && value != scalar.getUnsignedValue();
	}

	private String applyEquate(Instruction instruction, int opIndex) {
		if (instruction == null || opIndex == -1) {
			return null;
		}

		Scalar scalar = grabMatchingScalar(instruction, opIndex);
		if (scalar == null) {
			return null;
		}

		String equateName = action.convertToString(program, scalar);
		if (equateName.isEmpty()) {
			return null;
		}

		// Check for same named equate with different value.
		EquateTable equateTable = program.getEquateTable();
		Equate eqt = equateTable.getEquate(equateName);
		if (eqt != null && valuesAreDifferent(eqt, scalar)) {
			return "Couldn't convert to " + equateName + ". " + "Equate named " + equateName +
				" already exists with value of " + eqt.getValue() + ".";
		}

		Address address = instruction.getAddress();
		List<Equate> equates = equateTable.getEquates(address, opIndex);

		// First, clear any existing equates with the same value
		for (Equate equate : equates) {
			if (!valuesAreDifferent(equate, scalar)) {
				// Clears matching equates 
				ClearEquateCmd cmd = new ClearEquateCmd(equate.getName(), address, opIndex);
				cmd.applyTo(program);
			}
		}

		// Then, add the new equate
		SetEquateCmd cmd = new SetEquateCmd(equateName, address, opIndex, scalar.getValue());
		if (!cmd.applyTo(program)) {
			return "Couldn't convert to " + equateName + ". " + cmd.getStatusMsg();
		}

		return null;
	}

	private String applyEquateOverRange(ProgramSelection selection) {
		InstructionIterator it = program.getListing().getInstructions(context.getSelection(), true);
		String errorMessage = null;
		for (Instruction instruction : it) {
			for (int i = 0; i < instruction.getNumOperands(); i++) {
				String m = applyEquate(instruction, i);
				if (errorMessage == null && m != null) {
					errorMessage = m;
				}
			}
		}
		return errorMessage;
	}

	private Scalar grabMatchingScalar(Instruction instruction, int opIndex) {
		Scalar scalarAtCursor = action.getScalar(context);
		Scalar scalar = instruction.getScalar(opIndex);

		if (scalarAtCursor.equals(scalar)) {
			return scalar;
		}

		if (scalar == null) {
			List<?> opObjects = instruction.getDefaultOperandRepresentationList(opIndex);
			//@formatter:off
			Optional<Scalar> match = opObjects.stream()
				.filter(Scalar.class::isInstance)
				.map(Scalar.class::cast)
				.filter(s -> s.equals(scalarAtCursor))
				.findAny()
				;
			//@formatter:on

			if (match.isPresent()) {
				return match.get();
			}
		}

		return null;
	}

	@Override
	public String getName() {
		return "Convert to MotorolsFFP equate Command";
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {

		try {
			CodeUnit cu = action.getCodeUnit(context);
			if (cu instanceof Data) {
				return true;
			}

			if (context.hasSelection()) {
				msg = applyEquateOverRange(context.getSelection());
				return msg == null;
			}

			Instruction instruction = (Instruction) context.getCodeUnit();
			int opIndex = action.getOperandIndex(context);
			msg = applyEquate(instruction, opIndex);
		}
		catch (Exception e) {
			msg = "Exception applying the Convert to MotorolaFFP equate: " + e.getMessage();
		}

		return msg == null;
	}

	@Override
	public String getStatusMsg() {
		return msg;
	}

}
