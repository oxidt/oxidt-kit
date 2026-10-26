//! VTODO and VEVENT bodies for [`put_ics`](crate::put_ics), and reading them
//! back from [`query`](crate::query), built on the [`icalendar`] crate.
//!
//! `stamped` becomes `DTSTAMP`. It is a parameter instead of a read of the
//! clock, so a body depends only on its inputs.

use chrono::{DateTime, Days, Duration, NaiveDate, Utc};
use icalendar::{
    Calendar, CalendarDateTime, Component, DatePerhapsTime, EventLike, Todo, TodoStatus,
};

/// A point in time as calendars see it: a whole day, or an instant.
///
/// A zone-less local time has no variant here. Convert it to UTC in the
/// timezone you know it was written in before building the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    /// All-day: `VALUE=DATE`.
    Date(NaiveDate),
    /// An instant, written in UTC (`…Z`).
    Time(DateTime<Utc>),
}

impl From<When> for DatePerhapsTime {
    fn from(when: When) -> Self {
        match when {
            When::Date(date) => date.into(),
            When::Time(time) => time.into(),
        }
    }
}

impl When {
    /// From what a calendar stored. A `TZID` time is converted through the
    /// IANA zone it names; a floating time, or a zone the tz database doesn't
    /// know (an Outlook "W. Europe Standard Time"), is taken as UTC.
    fn read(stored: DatePerhapsTime) -> Option<Self> {
        Some(match stored {
            DatePerhapsTime::Date(date) => When::Date(date),
            DatePerhapsTime::DateTime(time) => {
                When::Time(time.try_into_utc().unwrap_or(match time {
                    CalendarDateTime::Floating(naive)
                    | CalendarDateTime::WithTimezone {
                        date_time: naive, ..
                    } => naive.and_utc(),
                    CalendarDateTime::Utc(utc) => utc,
                }))
            }
        })
    }
}

/// A calendar holding one VTODO. `priority` is iCalendar's 1 (highest) to 9
/// (lowest).
pub fn todo(
    uid: &str,
    summary: &str,
    description: &str,
    due: Option<When>,
    priority: Option<u32>,
    stamped: DateTime<Utc>,
) -> String {
    todo_body(&TodoBody {
        uid,
        summary,
        description: Some(description),
        due,
        priority,
        done: None,
        stamped,
    })
}

/// A calendar holding one VEVENT. Without an `end`, an all-day event lasts
/// its one day and a timed event one hour.
pub fn event(
    uid: &str,
    summary: &str,
    description: &str,
    start: When,
    end: Option<When>,
    location: Option<&str>,
    stamped: DateTime<Utc>,
) -> String {
    event_body(&EventBody {
        uid,
        summary,
        description: Some(description),
        start,
        end,
        location,
        rrule: None,
        stamped,
    })
}

/// Everything [`todo_body`] writes. `done: Some(at)` writes
/// `STATUS:COMPLETED`, plus `COMPLETED` when `at` is known; `None` writes no
/// status, which calendars read as open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TodoBody<'a> {
    pub uid: &'a str,
    pub summary: &'a str,
    pub description: Option<&'a str>,
    pub due: Option<When>,
    pub priority: Option<u32>,
    pub done: Option<Option<DateTime<Utc>>>,
    pub stamped: DateTime<Utc>,
}

/// A calendar holding the VTODO `body` describes.
pub fn todo_body(body: &TodoBody) -> String {
    let mut todo = Todo::new();
    todo.uid(body.uid)
        .summary(body.summary)
        .timestamp(body.stamped);
    if let Some(description) = body.description {
        todo.description(description);
    }
    if let Some(due) = body.due {
        todo.due(due);
    }
    if let Some(priority) = body.priority {
        todo.priority(priority);
    }
    if let Some(at) = body.done {
        todo.status(TodoStatus::Completed);
        if let Some(at) = at {
            todo.completed(at);
        }
    }
    Calendar::new().push(todo.done()).done().to_string()
}

/// Everything [`event_body`] writes. `rrule` is written as given
/// (`FREQ=WEEKLY;BYDAY=MO`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventBody<'a> {
    pub uid: &'a str,
    pub summary: &'a str,
    pub description: Option<&'a str>,
    pub start: When,
    pub end: Option<When>,
    pub location: Option<&'a str>,
    pub rrule: Option<&'a str>,
    pub stamped: DateTime<Utc>,
}

/// A calendar holding the VEVENT `body` describes. Without an `end`, an
/// all-day event lasts its one day and a timed event one hour.
pub fn event_body(body: &EventBody) -> String {
    let end = body.end.unwrap_or(match body.start {
        When::Date(date) => When::Date(date + Days::new(1)),
        When::Time(time) => When::Time(time + Duration::hours(1)),
    });
    let mut event = icalendar::Event::new();
    event
        .uid(body.uid)
        .summary(body.summary)
        .timestamp(body.stamped)
        .starts(body.start)
        .ends(end);
    if let Some(description) = body.description {
        event.description(description);
    }
    if let Some(location) = body.location {
        event.location(location);
    }
    if let Some(rrule) = body.rrule {
        event.add_property("RRULE", rrule);
    }
    Calendar::new().push(event.done()).done().to_string()
}

/// A VTODO read back from a calendar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadTodo {
    pub uid: String,
    pub summary: String,
    pub description: Option<String>,
    pub due: Option<When>,
    pub priority: Option<u32>,
    /// `STATUS:COMPLETED`, or a `COMPLETED` time without a status.
    pub completed: bool,
    pub completed_at: Option<DateTime<Utc>>,
}

/// A VEVENT read back from a calendar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadEvent {
    pub uid: String,
    pub summary: String,
    pub description: Option<String>,
    pub start: When,
    /// As stored; `DURATION`-only events have none.
    pub end: Option<When>,
    pub location: Option<String>,
    pub rrule: Option<String>,
}

/// The VTODOs in an iCalendar text. Entries without a `UID` are skipped; an
/// unreadable text yields none.
pub fn todos(ics: &str) -> Vec<ReadTodo> {
    let Ok(calendar) = ics.parse::<Calendar>() else {
        return Vec::new();
    };
    calendar
        .todos()
        .filter_map(|todo| {
            let completed_at = todo.get_completed();
            Some(ReadTodo {
                uid: todo.get_uid()?.to_string(),
                summary: todo.get_summary().unwrap_or_default().to_string(),
                description: todo.get_description().map(str::to_string),
                due: todo.get_due().and_then(When::read),
                priority: todo.get_priority(),
                completed: todo.get_status() == Some(TodoStatus::Completed)
                    || completed_at.is_some(),
                completed_at,
            })
        })
        .collect()
}

/// The VEVENTs in an iCalendar text. Entries without a `UID` or `DTSTART`
/// are skipped; an unreadable text yields none. A recurring series comes back
/// as its master and any overridden instances, each once.
pub fn events(ics: &str) -> Vec<ReadEvent> {
    let Ok(calendar) = ics.parse::<Calendar>() else {
        return Vec::new();
    };
    calendar
        .events()
        .filter_map(|event| {
            Some(ReadEvent {
                uid: event.get_uid()?.to_string(),
                summary: event.get_summary().unwrap_or_default().to_string(),
                description: event.get_description().map(str::to_string),
                start: event.get_start().and_then(When::read)?,
                end: event.get_end().and_then(When::read),
                location: event.get_location().map(str::to_string),
                rrule: event.property_value("RRULE").map(str::to_string),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID: &str = "00000000-0000-0000-0000-000000000000";

    fn stamped() -> DateTime<Utc> {
        "2026-07-01T00:00:00Z".parse().unwrap()
    }

    #[test]
    fn task_becomes_a_vtodo_with_due_and_priority() {
        let due = When::Time("2026-07-08T10:00:00+02:00".parse().unwrap());
        let ics = todo(
            UID,
            "Call Anna about the offer",
            "Call Anna about the offer\nshe wants numbers",
            Some(due),
            Some(1),
            stamped(),
        );
        assert!(ics.contains("BEGIN:VTODO"));
        assert!(ics.contains(&format!("UID:{UID}")));
        assert!(ics.contains("SUMMARY:Call Anna about the offer\r\n"));
        assert!(ics.contains("DUE:20260708T080000Z"));
        assert!(ics.contains("PRIORITY:1"));
        assert!(ics.contains("DTSTAMP:20260701T000000Z"));
    }

    #[test]
    fn all_day_event_ends_the_next_day() {
        let start = When::Date(NaiveDate::from_ymd_opt(2026, 9, 18).unwrap());
        let ics = event(UID, "Offsite", "", start, None, Some("Berlin"), stamped());
        assert!(ics.contains("BEGIN:VEVENT"));
        assert!(ics.contains("SUMMARY:Offsite"));
        assert!(ics.contains("DTSTART;VALUE=DATE:20260918"));
        assert!(ics.contains("DTEND;VALUE=DATE:20260919"));
        assert!(ics.contains("LOCATION:Berlin"));
    }

    #[test]
    fn timed_event_defaults_to_one_hour() {
        let start = When::Time("2026-09-18T07:00:00Z".parse().unwrap());
        let ics = event(UID, "Standup", "", start, None, None, stamped());
        assert!(ics.contains("DTSTART:20260918T070000Z"), "{ics}");
        assert!(ics.contains("DTEND:20260918T080000Z"), "{ics}");
        assert!(!ics.contains("LOCATION"), "{ics}");
    }

    #[test]
    fn a_completed_task_carries_its_status_and_time() {
        let done: DateTime<Utc> = "2026-07-02T09:30:00Z".parse().unwrap();
        let ics = todo_body(&TodoBody {
            uid: UID,
            summary: "Pay rent; then, relax",
            description: None,
            due: None,
            priority: None,
            done: Some(Some(done)),
            stamped: stamped(),
        });
        assert!(ics.contains("STATUS:COMPLETED"), "{ics}");
        assert!(ics.contains("COMPLETED:20260702T093000Z"), "{ics}");
        assert!(!ics.contains("DESCRIPTION"), "{ics}");

        let read = &todos(&ics)[0];
        assert_eq!(read.summary, "Pay rent; then, relax");
        assert!(read.completed);
        assert_eq!(read.completed_at, Some(done));
    }

    #[test]
    fn a_recurring_event_keeps_its_rule() {
        let ics = event_body(&EventBody {
            uid: UID,
            summary: "Standup",
            description: None,
            start: When::Time("2026-09-18T07:00:00Z".parse().unwrap()),
            end: None,
            location: None,
            rrule: Some("FREQ=WEEKLY;BYDAY=MO,WE"),
            stamped: stamped(),
        });
        assert!(ics.contains("RRULE:FREQ=WEEKLY;BYDAY=MO,WE"), "{ics}");
        assert_eq!(
            events(&ics)[0].rrule.as_deref(),
            Some("FREQ=WEEKLY;BYDAY=MO,WE")
        );
    }

    #[test]
    fn reading_converts_zoned_times_and_keeps_all_day_dates() {
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
BEGIN:VEVENT\r\nUID:a\r\nSUMMARY:Dentist\r\n\
DTSTART;TZID=Europe/Berlin:20260715T090000\r\nDTEND;TZID=Europe/Berlin:20260715T100000\r\n\
LOCATION:Hauptstr. 1\\, Kiel\r\nEND:VEVENT\r\n\
BEGIN:VEVENT\r\nUID:b\r\nSUMMARY:Holiday\r\nDTSTART;VALUE=DATE:20261003\r\nEND:VEVENT\r\n\
BEGIN:VEVENT\r\nSUMMARY:no uid\r\nDTSTART:20261003T100000Z\r\nEND:VEVENT\r\n\
BEGIN:VTODO\r\nUID:t\r\nSUMMARY:Taxes\r\nDUE;VALUE=DATE:20270531\r\nPRIORITY:1\r\n\
STATUS:NEEDS-ACTION\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
        let found = events(ics);
        assert_eq!(found.len(), 2, "the uid-less event is skipped");
        assert_eq!(
            found[0].start,
            When::Time("2026-07-15T07:00:00Z".parse().unwrap()),
            "09:00 in Berlin summer time is 07:00 UTC"
        );
        assert_eq!(found[0].location.as_deref(), Some("Hauptstr. 1, Kiel"));
        assert_eq!(
            found[1].start,
            When::Date(NaiveDate::from_ymd_opt(2026, 10, 3).unwrap())
        );
        assert_eq!(found[1].end, None);

        let tasks = todos(ics);
        assert_eq!(tasks.len(), 1);
        assert_eq!(
            tasks[0].due,
            Some(When::Date(NaiveDate::from_ymd_opt(2027, 5, 31).unwrap()))
        );
        assert_eq!(tasks[0].priority, Some(1));
        assert!(!tasks[0].completed);

        assert!(todos("not a calendar").is_empty());
    }
}
