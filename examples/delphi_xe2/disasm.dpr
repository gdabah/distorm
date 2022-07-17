////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : diStorm3
//  * Unit Name : disasm.dpr
//  * Purpose   : diStorm3 library sample
//  * Author    : Alexander (Rouse_) Bagel
//  * Version   : 1.0
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  * Project Page: https://github.com/AlexanderBagel/distorm
//  ****************************************************************************
//

program disasm;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  System.Classes,
  System.StrUtils,
  // Link the library into our project.
  distorm in 'include\distorm.pas',
  mnemonics in 'include\mnemonics.pas';

procedure PrintUsage;
begin
  Writeln('Usage: disasm.exe [-b16] [-b64] filename [memory offset]');
  Writeln('Raw disassembler output.');
  Writeln('Memory offset is origin of binary file in memory (address in hex).');
  Writeln('Default decoding mode is -b32.');
  Writeln('example:   disasm -b16 demo.com 789a');
end;

function IfThen(Value: Boolean; TrueValue, FalseValue: Integer): Integer;
begin
  if Value then
    Result := TrueValue
  else
    Result := FalseValue;
end;

const
  InstMax = 30;
var
  decodedInstructions: array [0..InstMax - 1] of TDecodedInst;
begin
  try
    // Version of used compiled library.
    var dver := get_distorm_version;
    Writeln(Format('diStorm version: %d.%d.%d', [dver shr 16, Byte(dver shr 8), Byte(dver)]));

    // Default decoding mode is 32 bits, could be set by command line.
    var dt: _DecodeType := Decode32Bits;

    // Default offset for buffer is 0, could be set in command line.
    var offset: _OffsetType := 0;

    // Check params.
    if not (ParamCount in [1..3]) then
    begin
      PrintUsage;
      ExitCode := -1;
      Exit;
    end;

    var ParamIndex: Integer := 1;
    case IndexText(ParamStr(ParamIndex), ['-b16', '-b64']) of
      0:
      begin
        dt := Decode16Bits;
        Inc(ParamIndex);
      end;
      1:
      begin
        dt := Decode64Bits;
        Inc(ParamIndex);
      end;
    end;

    if (ParamIndex > ParamCount) or not FileExists(ParamStr(ParamIndex)) then
    begin
      PrintUsage;
      Writeln('Filename is missing.');
      ExitCode := -1;
      Exit;
    end;

    var FilePath: string := ParamStr(ParamIndex);
    Inc(ParamIndex);

    // extra param
    if ParamIndex = ParamCount then
    begin
      var ParamOffset: Int64;
      if not TryStrToInt64('$' + ParamStr(ParamIndex), ParamOffset) then
      begin
        Writeln('Offset couldn''t be converted.');
        ExitCode := -1;
        Exit;
      end;
      offset := _OffsetType(ParamOffset);
    end;

    var M := TMemoryStream.Create;
    try
      M.LoadFromFile(FilePath);
      var pCursor: PByte := PByte(M.Memory) + offset;
      var res: TDecodeResult;
      var TotalCount := 100;
      repeat
        var ACount: LongWord;
        res := distorm_decode(_OffsetType(pCursor), pCursor, M.Size - NativeInt(offset),
          dt, @decodedInstructions[0], InstMax, @ACount);

        var ErrString := EmptyStr;
        case res of
          DECRES_NONE: ErrString := 'DECRES_NONE';
          // Null buffer? Decode type not 16/32/64?
          DECRES_INPUTERR: ErrString := 'DECRES_INPUTERR';
          DECRES_FILTERED: ErrString := 'DECRES_FILTERED';
        end;
        if ErrString <> EmptyStr then
        begin
          Writeln('Error: ', ErrString, '. Halting!');
          ExitCode := -2;
          Exit;
        end;

        for var I := 0 to ACount - 1 do
        begin
          Writeln(Format('%8x (%d) %-28s %s%s%s', [
            decodedInstructions[I].offset,
            decodedInstructions[i].size,
            string(PAnsiChar(@decodedInstructions[i].instructionHex.p[0])),
            string(PAnsiChar(@decodedInstructions[i].mnemonic.p[0])),
            System.StrUtils.IfThen(decodedInstructions[i].operands.length <> 0, ' ', EmptyStr),
            string(PAnsiChar(@decodedInstructions[i].operands.p[0]))
          ]));
          Inc(pCursor, decodedInstructions[i].size);
          Inc(offset, decodedInstructions[i].size);
          Dec(TotalCount);
          if TotalCount <= 0 then
            Break;
        end;

        if TotalCount <= 0 then
          Break;

      until res = DECRES_SUCCESS;
    finally
      M.Free;
    end;

  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
