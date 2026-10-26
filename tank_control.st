PROGRAM TankLevelControl
  VAR
    (* Digital Inputs (Sensors / Switches) *)
    LowLevelSensor AT %IX0.0 : BOOL;      (* Float switch: TRUE when water is at or above bottom *)
    HighLevelSensor AT %IX0.1 : BOOL;     (* Float switch: TRUE when water reaches top limit *)
    EmergencyStop AT %QX0.4 : BOOL := TRUE; (* NC E-Stop as a writable bit: TRUE = healthy; HMI/sim clears it to trip (inputs are read-only over Modbus) *)
    
    (* Digital Outputs (Actuators) *)
    PumpMotor AT %QX0.0 : BOOL;           (* Inflow pump contactor *)
    DrainValve AT %QX0.1 : BOOL;          (* Emergency or cycle drain valve *)
    AlarmBeacon AT %QX0.2 : BOOL;         (* Visual fault / high-level alarm *)

    (* Modbus Holding Registers (Analog / Setpoints) *)
    TankLevelRaw AT %QW2 : UINT;          (* Scaled 0 - 1000 (0.0% - 100.0%); holding reg 2, written by the level simulator *)
    HighThreshold AT %QW0 : UINT := 850;  (* Safe upper threshold (85.0%) *)
    LowThreshold AT %QW1 : UINT := 200;   (* Safe lower threshold (20.0%) *)
    
    (* Internal State *)
    ManualOverride AT %QX0.3 : BOOL;      (* TRUE: auto-fill suspended; HMI drives PumpMotor (%QX0.0) directly *)
  END_VAR

  (* Safety Interlock: If E-Stop is triggered or Tank exceeds maximum limit, shut down pump immediately *)
  IF NOT EmergencyStop OR (TankLevelRaw >= HighThreshold) THEN
    PumpMotor := FALSE;
    AlarmBeacon := (TankLevelRaw >= HighThreshold);
  ELSIF (TankLevelRaw <= LowThreshold) AND NOT ManualOverride THEN
    (* Automatic fill: Level is below minimum threshold *)
    PumpMotor := TRUE;
    AlarmBeacon := FALSE;
  ELSIF (TankLevelRaw > LowThreshold) AND (TankLevelRaw < HighThreshold) THEN
    (* Maintain current pump state (hysteresis) unless manual override is asserted *)
    PumpMotor := PumpMotor;
  END_IF;

  (* Drain logic protection *)
  IF HighLevelSensor OR (TankLevelRaw >= 950) THEN
    DrainValve := TRUE;
    AlarmBeacon := TRUE;
  ELSE
    DrainValve := FALSE;
  END_IF;

END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK TaskMain(INTERVAL := T#50ms, PRIORITY := 0);
    PROGRAM Inst0 WITH TaskMain : TankLevelControl;
  END_RESOURCE
END_CONFIGURATION
