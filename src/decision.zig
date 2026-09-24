const std = @import("std");

pub const default_max_request_bytes: usize = 1024 * 1024;
pub const default_max_response_bytes: usize = 4 * 1024 * 1024;
pub const default_model = "~typesafe/jev-latest";

pub const Adapter = enum {
    alpha_decisions,
    systemone_v1,

    pub fn parse(text: []const u8) !Adapter {
        if (std.mem.eql(u8, text, "alpha-decisions")) return .alpha_decisions;
        if (std.mem.eql(u8, text, "systemone-v1")) return .systemone_v1;
        return error.UnknownAdapter;
    }

    pub fn name(self: Adapter) []const u8 {
        return switch (self) {
            .alpha_decisions => "alpha-decisions",
            .systemone_v1 => "systemone-v1",
        };
    }

    /// Provider selection is explicit. Callers never probe or fail over between
    /// these two contracts.
    pub fn endpoint(self: Adapter) []const u8 {
        return switch (self) {
            .alpha_decisions => "https://openrouter.ai/api/alpha/decisions",
            .systemone_v1 => "https://openrouter.ai/api/v1/systemone",
        };
    }
};

pub const ValidatedRequest = struct {
    parsed: std.json.Parsed(std.json.Value),
    model: []const u8,

    pub fn deinit(self: *ValidatedRequest) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

pub const ValidatedResponse = struct {
    parsed: std.json.Parsed(std.json.Value),
    /// OpenRouter can resolve a moving alias to a dated model. Preserve the
    /// provider-returned value rather than assuming it equals the request.
    resolved_model: []const u8,

    pub fn deinit(self: *ValidatedResponse) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

pub fn validateRequest(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    max_bytes: usize,
) !ValidatedRequest {
    if (bytes.len == 0) return error.EmptyBody;
    if (bytes.len > max_bytes) return error.BodyTooLarge;

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
    });
    errdefer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |*object| object,
        else => return error.RequestMustBeObject,
    };

    const model = try requiredNonEmptyString(root, "model");
    const state = root.get("state") orelse return error.MissingState;
    if (!isStructured(state)) return error.InvalidState;

    const questions_value = root.get("questions") orelse return error.MissingQuestions;
    const questions = switch (questions_value) {
        .object => |*object| object,
        else => return error.QuestionsMustBeObject,
    };
    if (questions.count() == 0) return error.EmptyQuestions;

    var it = questions.iterator();
    while (it.next()) |entry| try validateQuestion(entry.value_ptr.*);

    return .{ .parsed = parsed, .model = model };
}

pub fn validateResponse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    max_bytes: usize,
) !ValidatedResponse {
    if (bytes.len == 0) return error.EmptyBody;
    if (bytes.len > max_bytes) return error.BodyTooLarge;

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
    });
    errdefer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |*object| object,
        else => return error.ResponseMustBeObject,
    };
    const model = try requiredNonEmptyString(root, "model");
    const answers_value = root.get("answers") orelse return error.MissingAnswers;
    const answers = switch (answers_value) {
        .object => |*object| object,
        else => return error.AnswersMustBeObject,
    };

    // Usage has evolved by gaining metadata. Validate the stable counters and
    // ignore optional/unknown additions such as provider cost breakdowns.
    const usage_value = root.get("usage") orelse return error.MissingUsage;
    const usage = switch (usage_value) {
        .object => |object| object,
        else => return error.UsageMustBeObject,
    };
    try validateTokenCount(usage.get("input_tokens") orelse return error.MissingInputTokens);
    try validateTokenCount(usage.get("output_tokens") orelse return error.MissingOutputTokens);

    var it = answers.iterator();
    while (it.next()) |entry| try validateAnswer(entry.value_ptr.*);

    return .{ .parsed = parsed, .resolved_model = model };
}

fn validateQuestion(value: std.json.Value) !void {
    const object = switch (value) {
        .object => |object| object,
        else => return error.QuestionMustBeObject,
    };
    const type_name = try requiredNonEmptyString(&object, "type");
    const instructions = object.get("instructions") orelse return error.MissingInstructions;
    if (!isStructured(instructions)) return error.InvalidInstructions;
    if (std.mem.eql(u8, type_name, "choice")) {
        const criteria = object.get("criteria") orelse return error.MissingCriteria;
        const choices = switch (criteria) {
            .object => |criteria_object| criteria_object,
            else => return error.ChoiceCriteriaMustBeObject,
        };
        if (choices.count() == 0) return error.EmptyChoiceCriteria;
        if (choices.count() > 255) return error.TooManyChoices;
        var iterator = choices.iterator();
        while (iterator.next()) |entry| {
            if (!isCriterion(entry.value_ptr.*)) return error.InvalidCriterion;
        }
        return;
    }

    if (std.mem.eql(u8, type_name, "noul")) {
        // Noul criteria are optional. When present, they are a map describing
        // both true and false; both descriptions use structured prompt values.
        if (object.get("criteria")) |criteria| {
            const meanings = switch (criteria) {
                .object => |criteria_object| criteria_object,
                else => return error.InvalidNoulCriteria,
            };
            const yes = meanings.get("true") orelse return error.InvalidNoulCriteria;
            const no = meanings.get("false") orelse return error.InvalidNoulCriteria;
            if (!isStructured(yes) or !isStructured(no)) return error.InvalidNoulCriteria;
        }
        return;
    }

    if (std.mem.eql(u8, type_name, "score")) {
        const criteria = object.get("criteria") orelse return error.MissingCriteria;
        const levels = switch (criteria) {
            .array => |array| array,
            else => return error.ScoreCriteriaMustBeArray,
        };
        if (levels.items.len < 2 or levels.items.len > 10) return error.InvalidScoreLevelCount;
        for (levels.items) |level| {
            if (!isStructured(level)) return error.InvalidCriterion;
        }
        return;
    }

    return error.UnsupportedQuestionType;
}

fn validateAnswer(value: std.json.Value) !void {
    const object = switch (value) {
        .object => |object| object,
        else => return error.AnswerMustBeObject,
    };
    const type_value = object.get("type") orelse return error.MissingAnswerType;
    const type_name = switch (type_value) {
        .string => |text| text,
        else => return error.InvalidAnswerType,
    };

    if (std.mem.eql(u8, type_name, "choice")) {
        const choice = object.get("choice") orelse return error.MissingChoice;
        if (choice != .string) return error.InvalidChoice;
    } else if (std.mem.eql(u8, type_name, "noul")) {
        const noul = object.get("noul") orelse return error.MissingNoul;
        const probability = number(noul) orelse return error.InvalidNoul;
        if (!std.math.isFinite(probability) or probability < 0 or probability > 1) return error.InvalidNoul;
    } else if (std.mem.eql(u8, type_name, "score")) {
        const score = object.get("score") orelse return error.MissingScore;
        const numeric_score = number(score) orelse return error.InvalidScore;
        if (!std.math.isFinite(numeric_score) or numeric_score < 0 or numeric_score > 9) return error.InvalidScore;
    } else {
        return error.UnsupportedAnswerType;
    }

    if (object.get("confidence")) |confidence| {
        const n = number(confidence) orelse return error.InvalidConfidence;
        if (!std.math.isFinite(n) or n < 0 or n > 1) return error.InvalidConfidence;
    }
    if (object.get("probabilities")) |probabilities| try validateProbabilities(probabilities);
    if (object.get("probs")) |probabilities| try validateProbabilities(probabilities);
}

fn validateProbabilities(value: std.json.Value) !void {
    const object = switch (value) {
        .object => |object| object,
        else => return error.InvalidProbabilities,
    };
    if (object.count() == 0) return error.InvalidProbabilities;
    var sum: f64 = 0;
    var iterator = object.iterator();
    while (iterator.next()) |entry| {
        const n = number(entry.value_ptr.*) orelse return error.InvalidProbability;
        if (!std.math.isFinite(n) or n < 0 or n > 1) return error.InvalidProbability;
        sum += n;
    }
    // Provider values are rounded for transport, so accept a narrow tolerance
    // while still rejecting incomplete or internally inconsistent maps.
    if (!std.math.isFinite(sum) or sum < 0.98 or sum > 1.02) return error.InvalidProbabilitySum;
}

fn requiredNonEmptyString(object: *const std.json.ObjectMap, key: []const u8) ![]const u8 {
    const value = object.get(key) orelse return error.MissingRequiredField;
    const text = switch (value) {
        .string => |text| text,
        else => return error.RequiredFieldMustBeString,
    };
    if (std.mem.trim(u8, text, " \t\r\n").len == 0) return error.EmptyRequiredField;
    return text;
}

fn isStructured(value: std.json.Value) bool {
    return switch (value) {
        .string, .object, .array => true,
        else => false,
    };
}

fn isCriterion(value: std.json.Value) bool {
    return switch (value) {
        .string, .object, .array, .null => true,
        else => false,
    };
}

fn number(value: std.json.Value) ?f64 {
    return switch (value) {
        .integer => |integer| @floatFromInt(integer),
        .float => |float| float,
        .number_string => |text| std.fmt.parseFloat(f64, text) catch null,
        else => null,
    };
}

fn validateTokenCount(value: std.json.Value) !void {
    switch (value) {
        .integer => |integer| if (integer < 0) return error.InvalidTokenCount,
        else => return error.InvalidTokenCount,
    }
}

test "adapter names and endpoints are explicit" {
    try std.testing.expectEqual(Adapter.alpha_decisions, try Adapter.parse("alpha-decisions"));
    try std.testing.expectEqual(Adapter.systemone_v1, try Adapter.parse("systemone-v1"));
    try std.testing.expectError(error.UnknownAdapter, Adapter.parse("auto"));
    try std.testing.expect(std.mem.endsWith(u8, Adapter.alpha_decisions.endpoint(), "/api/alpha/decisions"));
    try std.testing.expect(std.mem.endsWith(u8, Adapter.systemone_v1.endpoint(), "/api/v1/systemone"));
}

test "request validation accepts each primitive" {
    const input =
        \\{
        \\  "model":"typesafe/jev-1.13",
        \\  "state":{"ticket":"Printer is on fire"},
        \\  "questions":{
        \\    "route":{"type":"choice","instructions":"Pick a route","criteria":{"urgent":"Immediate danger","normal":"No danger"}},
        \\    "danger":{"type":"noul","instructions":"Is there danger?","criteria":{"true":"Physical danger is present","false":"No physical danger is present"}},
        \\    "severity":{"type":"score","instructions":"Rate severity","criteria":["minor","moderate","major"]}
        \\  }
        \\}
    ;
    var request = try validateRequest(std.testing.allocator, input, default_max_request_bytes);
    defer request.deinit();
    try std.testing.expectEqualStrings("typesafe/jev-1.13", request.model);
}

test "noul criteria are optional and noul response is a probability" {
    const input = "{\"model\":\"jev-latest\",\"state\":\"hello\",\"questions\":{\"q\":{\"type\":\"noul\",\"instructions\":\"Is this a greeting?\"}}}";
    var request = try validateRequest(std.testing.allocator, input, default_max_request_bytes);
    request.deinit();

    const response = "{\"model\":\"jev-1.13.0\",\"answers\":{\"q\":{\"type\":\"noul\",\"noul\":0.95}},\"usage\":{\"input_tokens\":2,\"output_tokens\":1}}";
    var validated = try validateResponse(std.testing.allocator, response, default_max_response_bytes);
    validated.deinit();
}

test "noul criteria require both meanings when present" {
    const missing_false =
        "{\"model\":\"m\",\"state\":\"hello\",\"questions\":{\"q\":{\"type\":\"noul\",\"instructions\":\"Greeting?\",\"criteria\":{\"true\":\"yes\"}}}}";
    try std.testing.expectError(
        error.InvalidNoulCriteria,
        validateRequest(std.testing.allocator, missing_false, default_max_request_bytes),
    );

    const complete =
        "{\"model\":\"m\",\"state\":\"hello\",\"questions\":{\"q\":{\"type\":\"noul\",\"instructions\":\"Greeting?\",\"criteria\":{\"true\":\"yes\",\"false\":\"no\"}}}}";
    var validated = try validateRequest(std.testing.allocator, complete, default_max_request_bytes);
    validated.deinit();
}

test "request validation enforces caps and bounds" {
    try std.testing.expectError(error.BodyTooLarge, validateRequest(std.testing.allocator, "{}", 1));
    const bad_state = "{\"model\":\"m\",\"state\":1,\"questions\":{\"q\":{\"type\":\"noul\",\"instructions\":\"x\",\"criteria\":\"y\"}}}";
    try std.testing.expectError(error.InvalidState, validateRequest(std.testing.allocator, bad_state, default_max_request_bytes));
    const bad_score = "{\"model\":\"m\",\"state\":\"s\",\"questions\":{\"q\":{\"type\":\"score\",\"instructions\":\"x\",\"criteria\":[\"only\"]}}}";
    try std.testing.expectError(error.InvalidScoreLevelCount, validateRequest(std.testing.allocator, bad_score, default_max_request_bytes));
    const bad_type = "{\"model\":\"m\",\"state\":\"s\",\"questions\":{\"q\":{\"type\":\"free_text\",\"instructions\":\"x\",\"criteria\":\"y\"}}}";
    try std.testing.expectError(error.UnsupportedQuestionType, validateRequest(std.testing.allocator, bad_type, default_max_request_bytes));
}

test "choice is limited to 255 criteria" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try output.writer.writeAll("{\"model\":\"m\",\"state\":\"s\",\"questions\":{\"q\":{\"type\":\"choice\",\"instructions\":\"x\",\"criteria\":{");
    for (0..256) |index| {
        if (index != 0) try output.writer.writeByte(',');
        try output.writer.print("\"c{d}\":\"v\"", .{index});
    }
    try output.writer.writeAll("}}}}");
    try std.testing.expectError(error.TooManyChoices, validateRequest(std.testing.allocator, output.written(), default_max_request_bytes));
}

test "response permits unknown metadata and rounded probability sums" {
    const response =
        \\{
        \\  "id":"dec_test",
        \\  "model":"typesafe/jev-1.13-20260901",
        \\  "provider":"TypeSafe",
        \\  "future_metadata":{"safe":true},
        \\  "answers":{"route":{"type":"choice","choice":"a","probabilities":{"a":0.333,"b":0.333,"c":0.333},"confidence":0.42,"extra":7}},
        \\  "usage":{"input_tokens":12,"output_tokens":4,"cost":0.001}
        \\}
    ;
    var validated = try validateResponse(std.testing.allocator, response, default_max_response_bytes);
    defer validated.deinit();
    try std.testing.expectEqualStrings("typesafe/jev-1.13-20260901", validated.resolved_model);
}

test "request and response reject duplicate JSON fields" {
    const duplicate_request =
        "{\"model\":\"m\",\"model\":\"other\",\"state\":\"s\",\"questions\":{\"q\":{\"type\":\"noul\",\"instructions\":\"x\"}}}";
    try std.testing.expectError(
        error.DuplicateField,
        validateRequest(std.testing.allocator, duplicate_request, default_max_request_bytes),
    );

    const duplicate_response =
        "{\"model\":\"m\",\"answers\":{\"q\":{\"type\":\"noul\",\"noul\":0.5,\"noul\":0.6}},\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}";
    try std.testing.expectError(
        error.DuplicateField,
        validateResponse(std.testing.allocator, duplicate_response, default_max_response_bytes),
    );
}

test "response rejects unknown answer types and invalid scores" {
    const unknown =
        "{\"model\":\"m\",\"answers\":{\"q\":{\"type\":\"free_text\",\"text\":\"unsafe extension\"}},\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}";
    try std.testing.expectError(
        error.UnsupportedAnswerType,
        validateResponse(std.testing.allocator, unknown, default_max_response_bytes),
    );

    const too_high =
        "{\"model\":\"m\",\"answers\":{\"q\":{\"type\":\"score\",\"score\":9.01}},\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}";
    try std.testing.expectError(
        error.InvalidScore,
        validateResponse(std.testing.allocator, too_high, default_max_response_bytes),
    );

    const non_finite =
        "{\"model\":\"m\",\"answers\":{\"q\":{\"type\":\"score\",\"score\":1e999}},\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}";
    try std.testing.expectError(
        error.InvalidScore,
        validateResponse(std.testing.allocator, non_finite, default_max_response_bytes),
    );
}

test "probability maps are bounded nonempty and approximately normalized" {
    const cases = [_][]const u8{
        "{\"model\":\"m\",\"answers\":{\"q\":{\"type\":\"choice\",\"choice\":\"a\",\"probabilities\":{}}},\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}",
        "{\"model\":\"m\",\"answers\":{\"q\":{\"type\":\"choice\",\"choice\":\"a\",\"probabilities\":{\"a\":1.1}}},\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}",
        "{\"model\":\"m\",\"answers\":{\"q\":{\"type\":\"choice\",\"choice\":\"a\",\"probabilities\":{\"a\":0.7,\"b\":0.2}}},\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}",
        "{\"model\":\"m\",\"answers\":{\"q\":{\"type\":\"choice\",\"choice\":\"a\",\"probabilities\":{\"a\":0.7,\"b\":0.4}}},\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}",
    };
    const expected = [_]anyerror{
        error.InvalidProbabilities,
        error.InvalidProbability,
        error.InvalidProbabilitySum,
        error.InvalidProbabilitySum,
    };
    for (cases, expected) |input, expected_error| {
        try std.testing.expectError(
            expected_error,
            validateResponse(std.testing.allocator, input, default_max_response_bytes),
        );
    }

    const rounded =
        "{\"model\":\"m\",\"answers\":{\"q\":{\"type\":\"choice\",\"choice\":\"a\",\"probabilities\":{\"a\":0.333,\"b\":0.333,\"c\":0.333}}},\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}";
    var validated = try validateResponse(std.testing.allocator, rounded, default_max_response_bytes);
    validated.deinit();
}

fn requestAllocationFailureCase(allocator: std.mem.Allocator) !void {
    const input =
        \\{"model":"m","state":{"task":"inspect"},"questions":{"route":{"type":"choice","instructions":"route","criteria":{"read":"read","edit":"edit"}},"risk":{"type":"noul","instructions":"risk?","criteria":{"true":"yes","false":"no"}},"impact":{"type":"score","instructions":"impact","criteria":["low","high"]}}}
    ;
    var validated = try validateRequest(allocator, input, default_max_request_bytes);
    defer validated.deinit();
}

fn responseAllocationFailureCase(allocator: std.mem.Allocator) !void {
    const input =
        \\{"model":"m-20260923","answers":{"route":{"type":"choice","choice":"read","probabilities":{"read":0.7,"edit":0.3}},"risk":{"type":"noul","noul":0.1},"impact":{"type":"score","score":1.0,"confidence":0.9}},"usage":{"input_tokens":3,"output_tokens":2}}
    ;
    var validated = try validateResponse(allocator, input, default_max_response_bytes);
    defer validated.deinit();
}

test "decision request validation is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, requestAllocationFailureCase, .{});
}

test "decision response validation is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, responseAllocationFailureCase, .{});
}
